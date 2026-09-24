package com.vymalo.keycloak.webhook

import com.rabbitmq.client.Channel
import com.rabbitmq.client.Connection
import com.vymalo.keycloak.webhook.models.AmqpConfig
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeoutException

/**
 * Publishes each event as one message to a RabbitMQ exchange, on the Keycloak request thread.
 * The default mode; [AsyncAmqpTransport] is the opt-in alternative.
 *
 * One connection and channel serve the whole server. Publishing is serialized: a
 * channel waiting for confirms must not be shared mid-flight, and it keeps reconnects
 * race-free. If the connection is gone, [publish] reconnects inline (three attempts,
 * a second apart) and otherwise drops the event with a log line.
 */
class AmqpTransport(private val config: AmqpConfig) : Transport {

    private val connections = AmqpConnections(config) { isAutomaticRecoveryEnabled = true }

    /** Built once: identical for every message, except the message id when that is on. */
    private val baseProperties = AmqpMessage.properties(config)

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
            val message = AmqpMessage.of(payload, config, baseProperties)
            channel.basicPublish(config.exchange, message.routingKey, message.properties, message.body)
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
        val connection = connections.open().also { connection = it }
        return connection.createChannel()
            .also { if (config.publisherConfirm) it.confirmSelect() }
            .also { channel = it }
    }

    @Synchronized
    override fun close() = closeQuietly()

    private fun closeQuietly() {
        AmqpConnections.shutDown(connection, channel)
        channel = null
        connection = null
    }

    private companion object {
        private const val RECONNECT_ATTEMPTS = 3
        private const val RECONNECT_DELAY_MS = 1_000L
        private val logger = LoggerFactory.getLogger(AmqpTransport::class.java)
    }
}
