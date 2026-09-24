package com.vymalo.keycloak.webhook

import com.vymalo.keycloak.webhook.helper.cf
import com.vymalo.keycloak.webhook.helper.eventsTakenKey
import org.keycloak.Config
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ServerInfoAwareProviderFactory
import org.slf4j.LoggerFactory

abstract class AbstractWebhookEventListenerFactory(
    private val delegate: WebhookHandler
) : EventListenerProviderFactory,
    ServerInfoAwareProviderFactory,
    EventListenerProvider,
    WebhookHandler by delegate {
    private var filter: EventFilter = EventFilter.ALL

    override fun getOperationalInfo() = mapOf("version" to "0.10.0-rc.1")

    companion object {
        @JvmStatic
        private val LOG = LoggerFactory.getLogger(AbstractWebhookEventListenerFactory::class.java)
    }

    override fun create(session: KeycloakSession): EventListenerProvider {
        ensureParametersInit()
        return this
    }

    @Synchronized
    private fun ensureParametersInit() {
        synchronized(delegate) {
            delegate.initHandler()
            filter = EventFilter.parse(eventsTakenKey.cf())
        }
    }

    override fun init(config: Config.Scope) {}

    override fun postInit(factory: KeycloakSessionFactory) {}

    override fun onEvent(event: Event) = send(event.toPayload())

    override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) = send(event.toPayload())

    private fun send(request: WebhookPayload) {
        if (!filter.accepts(request.type)) {
            LOG.debug("Event {} not in the taken list. Will be skipped ({}).", request.type, filter)
            return
        }

        try {
            LOG.debug("Sending [{}] webhook for event type {}: {}", delegate.getId(), request.type, request)
            delegate.sendWebhook(request)
        } catch (e: Throwable) {
            LOG.error("Could not send webhook", e)
        }
    }
}
