package ru.ratauth.gatekeeper.autoconfigure;

import org.reactivestreams.Subscription;
import org.slf4j.MDC;
import reactor.core.CoreSubscriber;
import reactor.util.context.Context;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * https://github.com/archie-swif/webflux-mdc
 * Helper that copies the state of Reactor [Context] to MDC on the #onNext function.
 */
public class MdcContextLifter<T> implements CoreSubscriber<T> {

    private static final String LOG_CONTEXT_MAP = "log-context-map";

    CoreSubscriber<T> coreSubscriber;

    public MdcContextLifter(CoreSubscriber<T> coreSubscriber) {
        this.coreSubscriber = coreSubscriber;
    }

    @Override
    public void onSubscribe(Subscription subscription) {
        coreSubscriber.onSubscribe(subscription);
    }

    @Override
    public void onNext(T obj) {
        copyToMdc(coreSubscriber.currentContext());
        coreSubscriber.onNext(obj);
    }

    @Override
    public void onError(Throwable t) {
        coreSubscriber.onError(t);
    }

    @Override
    public void onComplete() {
        coreSubscriber.onComplete();
    }

    @Override
    public Context currentContext() {
        return coreSubscriber.currentContext();
    }

    /**
     * Extension function for the Reactor [Context]. Copies the current context to the MDC, if context is empty clears the MDC.
     * State of the MDC after calling this method should be same as Reactor [Context] state.
     * One thread-local access only.
     */
    private void copyToMdc(Context context) {

        if (!context.isEmpty()) {
            Objects.requireNonNull(context.getOrDefault(LOG_CONTEXT_MAP, new ConcurrentHashMap<String, String>()))
                    .forEach(MDC::put);
//            Optional.ofNullable(MDC.getCopyOfContextMap()).ifPresent(map::putAll);
//            MDC.setContextMap(map);
//            MDC.put();
        } else {
            MDC.clear();
        }
    }

}