package com.vymalo.keycloak.webhook

import com.google.gson.Gson
import com.rabbitmq.client.AMQP.BasicProperties
import com.rabbitmq.client.Channel
import com.rabbitmq.client.Connection
import com.rabbitmq.client.ConnectionFactory
import com.vymalo.keycloak.webhook.models.AmqpConfig
import org.keycloak.utils.MediaType
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeoutException

/**
 * Publishes each event as one message to a RabbitMQ exchange.
 *
 * One connection and channel serve the whole server. Publishing is serialized: a
 * channel waiting for confirms must not be shared mid-flight, and it keeps reconnects
 * race-free. If the connection is gone, [publish] reconnects inline (three attempts,
 * a second apart) and otherwise drops the event with a log line. That blocking retry
 * is the existing behaviour; a non-blocking mode comes later as an opt-in.
 */
class AmqpTransport(private val config: AmqpConfig) : Transport {

    private val connectionFactory = ConnectionFactory().apply {
        username = config.username
        password = config.password
        virtualHost = config.vHost
        host = config.host
        port = config.port
        isAutomaticRecoveryEnabled = true
        if (config.ssl) useSslProtocol()
    }

    // Guarded by `this`; only touched from synchronized methods.
    private var connection: Connection? = null
    private var channel: Channel? = null

    @Synchronized
    override fun publish(payload: WebhookPayload) {
        val channel = openChannel() ?: run {
            logger.warn("AMQP channel or connection is still closed. Unable to send webhook: {}", payload)
            return
        }
        try {
            channel.basicPublish(
                config.exchange,
                routingKey(payload),
                MESSAGE_PROPERTIES,
                gson.toJson(payload).toByteArray(Charsets.UTF_8),
            )
            if (config.publisherConfirm) channel.waitForConfirms(config.confirmTimeoutMs)
            logger.debug("Webhook message sent: {}", payload)
        } catch (e: TimeoutException) {
            logger.error(
                "Publisher confirm timeout after {}ms — message delivery could not be verified, request: {}",
                config.confirmTimeoutMs, payload, e,
            )
        } catch (e: Exception) {
            logger.error("Failed to send webhook message", e)
        }
    }

    /** The open channel, reconnecting when needed; null if the broker stays unreachable. */
    private fun openChannel(): Channel? {
        channel?.takeIf { it.isOpen && connection?.isOpen == true }?.let { return it }
        for (attempt in 1..RECONNECT_ATTEMPTS) {
            try {
                return connect()
            } catch (e: Exception) {
                logger.warn("Attempt {} to (re)connect to AMQP failed: {}", attempt, e.message, e)
                if (attempt < RECONNECT_ATTEMPTS) Thread.sleep(RECONNECT_DELAY_MS)
            }
        }
        logger.error("Unable to re-establish connection after {} attempts.", RECONNECT_ATTEMPTS)
        return null
    }

    /**
     * Fresh connection and channel. Confirm mode is per channel, so it is switched on
     * again every time; forgetting that on reconnect would make every later confirm wait fail.
     */
    private fun connect(): Channel {
        closeQuietly()
        val connection = connectionFactory.newConnection().also { connection = it }
        return connection.createChannel()
            .also { if (config.publisherConfirm) it.confirmSelect() }
            .also { channel = it }
    }

    @Synchronized
    override fun close() = closeQuietly()

    /**
     * A dropped connection must still be shut down: with automatic recovery on, it reports
     * closed but keeps reconnecting in the background, and would come back as a leaked
     * second connection. abort() stops that and never throws; close() is kept for open
     * connections so pending frames are flushed.
     */
    private fun closeQuietly() {
        runCatching { channel?.takeIf { it.isOpen }?.close() }
            .onFailure { logger.warn("Error closing channel", it) }
        connection?.let { connection ->
            if (connection.isOpen) {
                runCatching { connection.close() }.onFailure { logger.warn("Error closing connection", it) }
            } else {
                connection.abort()
            }
        }
        channel = null
        connection = null
    }

    companion object {
        private const val RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_DELAY_MS = 1_000L

        private val gson = Gson()
        private val logger = LoggerFactory.getLogger(AmqpTransport::class.java)

        /**
         * The same for every message. `__TypeId__` is the header Spring AMQP reads to pick
         * the target class, so Spring consumers can deserialize without extra mapping.
         */
        internal val MESSAGE_PROPERTIES: BasicProperties = BasicProperties.Builder()
            .appId("Keycloak/Kotlin")
            .headers(mapOf<String, Any>("__TypeId__" to WebhookPayload::class.java.name))
            .contentType(MediaType.APPLICATION_JSON)
            .contentEncoding("UTF-8")
            .build()

        /** `KC_CLIENT.<realm>.<client>.<user>.<type>` so consumers can bind on any part, e.g. `KC_CLIENT.*.*.*.LOGIN`. */
        internal fun routingKey(payload: WebhookPayload) =
            "KC_CLIENT.${payload.realmId}.${payload.clientId ?: "xxx"}.${payload.userId ?: "xxx"}.${payload.type}"
    }
}
