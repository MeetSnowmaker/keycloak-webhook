package com.vymalo.keycloak.webhook

import com.google.gson.Gson
import com.vymalo.keycloak.webhook.helper.eventsTakenKey
import com.vymalo.keycloak.webhook.testing.Fixtures
import com.vymalo.keycloak.webhook.testing.KeycloakSim.inSession
import com.vymalo.keycloak.webhook.testing.withConfig
import org.keycloak.events.EventType
import java.util.logging.Handler
import java.util.logging.Level
import java.util.logging.LogRecord
import java.util.logging.Logger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * How Keycloak events become webhook payloads, and which ones get through the
 * `WEBHOOK_EVENTS_TAKEN` filter. Transport-independent: a recording transport
 * stands in for AMQP/HTTP/Syslog.
 */
class EventListenerTest {

    /** Keeps what would have been sent, serialized the way AMQP and Syslog serialize it. */
    private class RecordingTransport : Transport {
        val sent = mutableListOf<String>()
        override fun publish(payload: WebhookPayload) {
            sent += Gson().toJson(payload)
        }
    }

    private class Factory(transport: Transport) : WebhookEventListenerFactory("recording", { transport })

    private val handler = RecordingTransport()
    private val factory = Factory(handler)

    @Test
    fun `user event maps to the documented payload`() {
        factory.inSession { it.onEvent(Fixtures.loginEvent()) }
        assertEquals(listOf(Fixtures.PayloadJson.LOGIN), handler.sent)
    }

    @Test
    fun `admin event maps resource and operation into the type`() {
        factory.inSession { it.onEvent(Fixtures.adminEvent(), true) }
        assertEquals(listOf(Fixtures.PayloadJson.ADMIN), handler.sent)
    }

    @Test
    fun `optional fields left empty by Keycloak are omitted, not null`() {
        factory.inSession { it.onEvent(Fixtures.anonymousEvent()) }
        assertEquals(listOf(Fixtures.PayloadJson.ANONYMOUS), handler.sent)
    }

    @Test
    fun `without a filter every event is sent`() = withConfig(eventsTakenKey to null) {
        factory.inSession {
            it.onEvent(Fixtures.loginEvent())
            it.onEvent(Fixtures.adminEvent(), false)
        }
        assertEquals(2, handler.sent.size)
    }

    @Test
    fun `filter keeps listed types and tolerates spaces around names`() =
        withConfig(eventsTakenKey to " LOGIN , USER-CREATE ") {
            val logout = Fixtures.loginEvent().apply { type = EventType.LOGOUT }
            factory.inSession {
                it.onEvent(Fixtures.loginEvent())
                it.onEvent(logout)
                it.onEvent(Fixtures.adminEvent(), false)
            }
            assertEquals(listOf(Fixtures.PayloadJson.LOGIN, Fixtures.PayloadJson.ADMIN), handler.sent)
        }

    @Test
    fun `a failing transport never breaks the Keycloak request, and the failure is logged`() {
        val failing = Factory(object : Transport {
            override fun publish(payload: WebhookPayload) = error("broker down")
        })

        // Getting past onEvent means no exception escaped to Keycloak.
        val logged = errorsLoggedBy(WebhookEventListener::class.java) {
            failing.inSession { it.onEvent(Fixtures.loginEvent()) }
        }

        val record = logged.single()
        assertEquals("Could not send webhook", record.message)
        assertEquals("broker down", record.thrown?.message)
    }

    /**
     * Collects what [owner] logs at error level while [block] runs, and keeps it off the
     * console. Keycloak's dependencies put Quarkus' JBoss LogManager behind SLF4J here,
     * the same path production logs take, and it is a java.util.logging LogManager, so a
     * plain JUL handler sees every record.
     */
    private fun errorsLoggedBy(owner: Class<*>, block: () -> Unit): List<LogRecord> {
        val logger = Logger.getLogger(owner.name)
        val records = mutableListOf<LogRecord>()
        val capture = object : Handler() {
            override fun publish(record: LogRecord) {
                if (record.level.intValue() >= Level.SEVERE.intValue()) records += record
            }
            override fun flush() {}
            override fun close() {}
        }
        val inheritedHandlers = logger.useParentHandlers
        logger.addHandler(capture)
        logger.useParentHandlers = false
        try {
            block()
        } finally {
            logger.removeHandler(capture)
            logger.useParentHandlers = inheritedHandlers
        }
        assertTrue(records.isNotEmpty(), "expected ${owner.simpleName} to log an error")
        return records
    }
}
