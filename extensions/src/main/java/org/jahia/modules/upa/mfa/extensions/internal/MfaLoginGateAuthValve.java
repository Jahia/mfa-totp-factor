package org.jahia.modules.upa.mfa.extensions.internal;

import org.apache.commons.lang3.StringUtils;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.BaseAuthValve;
import org.jahia.pipelines.Pipeline;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.SpringContextSingleton;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Closes the password-only {@code /cms/login} MFA bypass at its root: a Jahia authentication valve
 * inserted BEFORE the default password-login valve ({@code LoginEngineAuthValve}).
 * <p>
 * <b>Why a valve and not just the servlet filter?</b> Jahia authenticates a {@code /cms/login} POST
 * inside its authentication pipeline, and that pipeline runs BEFORE module servlet filters. So a
 * POST carrying a valid username/password establishes an authenticated session BEFORE
 * {@link MfaLoginGateFilter} ever runs - the filter can then only redirect the <i>response</i>,
 * while the session is already authenticated. The result is that a password-only {@code /cms/login}
 * POST fully bypasses MFA on an enforcing site (the filter appears to gate GET only because a GET
 * carries no credentials to authenticate). Running as a valve positioned before
 * {@code LoginEngineAuthValve}, this component can short-circuit the pipeline and block the login
 * BEFORE any authentication happens. The servlet filter stays as defense-in-depth (mainly the GET
 * case); both share {@link MfaLoginGateDecision} so they never drift apart.
 * <p>
 * Pipeline protocol: {@link ValveContext#invokeNext(Object)} CONTINUES the pipeline (let the login
 * proceed); NOT calling it short-circuits, and this valve then writes the response itself (a redirect
 * to the configured MFA login page, or {@code 403}).
 * <p>
 * The block is independent of the {@code loginGate.enabled} hard-gate switch: that switch only tunes
 * the servlet filter's GET behavior, but the password-login POST bypass must ALWAYS be closed when a
 * site enforces MFA. Only the IP whitelist (the operator's emergency door) and the absence of
 * enforcement let a login through.
 * <p>
 * <b>Registration:</b> this is a Declarative Services component (the module has no Spring context).
 * On {@code @Activate} it resolves Jahia's {@code authPipeline} bean via {@link SpringContextSingleton}
 * and inserts itself immediately before {@code LoginEngineAuthValve} using the {@link BaseAuthValve}
 * helper; on {@code @Deactivate} it removes itself. (It still extends {@link BaseAuthValve} for the
 * id/enabled bookkeeping and the add/remove helpers; the Spring auto-registration base is not used
 * because Jahia does not build a Spring context for this bnd/DS bundle.)
 */
@Component(service = MfaLoginGateAuthValve.class, immediate = true)
public class MfaLoginGateAuthValve extends BaseAuthValve {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginGateAuthValve.class);

    static final String VALVE_ID = "MfaLoginGateAuthValve";
    /** The default password-login valve we must run in front of. */
    static final String LOGIN_ENGINE_VALVE_ID = "LoginEngineAuthValve";
    /** Jahia core Spring bean id for the authentication pipeline. */
    static final String AUTH_PIPELINE_BEAN = "authPipeline";

    private static final String PARAM_USERNAME = "username";
    private static final String PARAM_PASSWORD = "password";

    private MfaLoginGateDecision decision;
    private Pipeline authPipeline;

    @Reference
    public void setDecision(MfaLoginGateDecision decision) {
        this.decision = decision;
    }

    @Activate
    public void activate() {
        initialize();
        Object bean = SpringContextSingleton.getBean(AUTH_PIPELINE_BEAN);
        if (bean instanceof Pipeline) {
            authPipeline = (Pipeline) bean;
            // position = -1 so the helper falls through to positionBefore (LoginEngineAuthValve).
            addValve(authPipeline, -1, null, LOGIN_ENGINE_VALVE_ID);
            logger.info("MFA login gate auth valve registered before {} (blocks password-only "
                    + "/cms/login before authentication while a site enforces MFA)", LOGIN_ENGINE_VALVE_ID);
        } else {
            logger.error("Could not resolve the '{}' pipeline bean - the MFA /cms/login POST gate is NOT "
                    + "active (password-only login would bypass MFA). Got: {}", AUTH_PIPELINE_BEAN, bean);
        }
    }

    @Deactivate
    public void deactivate() {
        if (authPipeline != null) {
            removeValve(authPipeline);
            authPipeline = null;
            logger.info("MFA login gate auth valve unregistered from the auth pipeline");
        }
    }

    @Override
    public void initialize() {
        setId(VALVE_ID);
        setEnabled(true);
    }

    @Override
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        if (!(context instanceof AuthValveContext)) {
            valveContext.invokeNext(context);
            return;
        }
        AuthValveContext authContext = (AuthValveContext) context;
        HttpServletRequest request = authContext.getRequest();
        HttpServletResponse response = authContext.getResponse();

        // Mirror LoginEngineAuthValve's trigger: it only authenticates when BOTH username and
        // password are present. A request without both is no password-login attempt - the valve has
        // nothing to gate, so let the pipeline continue.
        if (!isPasswordLoginAttempt(request)) {
            valveContext.invokeNext(context);
            return;
        }

        MfaLoginGateDecision currentDecision = lookupDecision();
        if (currentDecision == null) {
            // The decision component is not bound yet (bundle starting / stopping). We cannot decide,
            // so allow the pipeline to proceed: the servlet filter still covers this endpoint. Logged
            // as a warning because, during this window, a password-only POST is not blocked here.
            logger.warn("MFA login gate auth valve: decision component unavailable, cannot evaluate the "
                    + "/cms/login gate - letting the login proceed (servlet filter still applies)");
            valveContext.invokeNext(context);
            return;
        }

        // The emergency door: a whitelisted client is always let through (matches the filter).
        if (currentDecision.isClientWhitelisted(request)) {
            valveContext.invokeNext(context);
            return;
        }

        // The decisive block: a gated password login must NOT authenticate. Short-circuit the
        // pipeline (do not invokeNext) and write the response ourselves.
        if (currentDecision.isGated(request)) {
            block(currentDecision, request, response);
            return;
        }

        valveContext.invokeNext(context);
    }

    /**
     * Block the login: redirect to the configured MFA login page when a distinct one is resolvable,
     * else {@code 403}. Never chains the pipeline - returning without {@code invokeNext} stops the
     * authentication.
     */
    private void block(MfaLoginGateDecision currentDecision, HttpServletRequest request, HttpServletResponse response)
            throws PipelineException {
        try {
            String distinctLogin = currentDecision.resolveDistinctLoginUrl(request);
            if (distinctLogin != null) {
                logger.debug("MFA login gate auth valve: blocking password-only /cms/login, redirecting to "
                        + "the configured MFA login page");
                response.sendRedirect(distinctLogin);
            } else {
                logger.warn("MFA login gate auth valve: blocked password-only /cms/login (MFA enrollment "
                        + "enforced and IP not whitelisted; no distinct MFA login page configured to redirect "
                        + "to - set loginUrl on PID org.jahia.modules.mfa.extensions or the site's MFA "
                        + "administration page)");
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        } catch (IOException e) {
            throw new PipelineException("Failed to write the MFA login gate block response", e);
        }
    }

    /** A {@code /cms/login} POST is a password-login attempt only when BOTH credentials are present. */
    private static boolean isPasswordLoginAttempt(HttpServletRequest request) {
        return StringUtils.isNotEmpty(request.getParameter(PARAM_USERNAME))
                && StringUtils.isNotEmpty(request.getParameter(PARAM_PASSWORD));
    }

    /** The bound decision component. Overridable seam so unit tests can inject a stub. */
    protected MfaLoginGateDecision lookupDecision() {
        return decision;
    }

    // A valve's identity in the pipeline is its id (see BaseAuthValve); the injected decision and
    // pipeline are runtime wiring, not identity. Delegate so equals/hashCode stay id-based.
    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
