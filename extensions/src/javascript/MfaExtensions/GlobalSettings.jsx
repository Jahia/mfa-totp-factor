import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {ConfigurationQuery, SaveConfigurationMutation} from './GlobalSettings.gql';

/** Map a GraphQL/Apollo error to an i18n key for this screen. */
function mapError(err) {
    const gql = err && err.graphQLErrors && err.graphQLErrors[0];
    const msg = (gql && gql.message) || (err && err.message) || 'unknown_error';
    if (msg.indexOf('unknown_factor') !== -1) {
        return 'settings.errors.unknownFactor';
    }

    if (msg.indexOf('invalid_grace_days') !== -1) {
        return 'settings.errors.invalidGraceDays';
    }

    if (msg.indexOf('invalid_whitelist') !== -1) {
        return 'settings.errors.invalidWhitelist';
    }

    if (msg.indexOf('invalid_email') !== -1) {
        return 'settings.errors.invalidEmail';
    }

    if (msg.indexOf('Permission denied') !== -1 || msg.indexOf('permission') !== -1) {
        return 'settings.errors.permissionDenied';
    }

    return 'settings.errors.generic';
}

/**
 * Server administration panel for the global MFA configuration
 * (PID org.jahia.modules.mfa.extensions): the enforcement policy (which installed factors are
 * required, with the grace window), the /cms/login gate, and the global login/logout routing.
 * Edits are persisted to the Karaf configuration and hot-reloaded by the consuming components.
 */
const GlobalSettings = () => {
    const {t} = useTranslation('mfa-factors-extensions');

    const [registeredFactors, setRegisteredFactors] = useState([]);
    const [enforcedFactors, setEnforcedFactors] = useState([]);
    const [graceDays, setGraceDays] = useState(0);
    const [gateEnabled, setGateEnabled] = useState(false);
    const [trustForwardedFor, setTrustForwardedFor] = useState(true);
    const [ipWhitelist, setIpWhitelist] = useState('');
    const [loginUrl, setLoginUrl] = useState('');
    const [logoutUrl, setLogoutUrl] = useState('');
    const [resetNotifyEmail, setResetNotifyEmail] = useState('');
    const [savedAt, setSavedAt] = useState(null);
    const [errorKey, setErrorKey] = useState(null);

    const {data, loading} = useQuery(ConfigurationQuery, {fetchPolicy: 'network-only'});

    useEffect(() => {
        const c = data && data.mfaExtensionsConfiguration;
        if (c) {
            setRegisteredFactors(c.registeredFactors || []);
            setEnforcedFactors(c.enforcedFactors || []);
            setGraceDays(Number(c.graceDays) || 0);
            setGateEnabled(Boolean(c.loginGateEnabled));
            setTrustForwardedFor(c.loginGateTrustForwardedFor !== false);
            setIpWhitelist(c.loginGateIpWhitelist || '');
            setLoginUrl(c.loginUrl || '');
            setLogoutUrl(c.logoutUrl || '');
            setResetNotifyEmail(c.resetNotifyEmail || '');
        }
    }, [data]);

    const [saveMutation, {loading: saving}] = useMutation(SaveConfigurationMutation, {
        onCompleted: () => {
            setErrorKey(null);
            setSavedAt(Date.now());
        },
        onError: err => setErrorKey(mapError(err))
    });

    const toggleFactor = factor => {
        setEnforcedFactors(current => (current.includes(factor) ?
            current.filter(f => f !== factor) :
            [...current, factor]));
    };

    const save = () => {
        setSavedAt(null);
        setErrorKey(null);
        saveMutation({
            variables: {
                enforcedFactors,
                graceDays: Math.max(0, Number(graceDays) || 0),
                loginGateEnabled: gateEnabled,
                loginGateTrustForwardedFor: trustForwardedFor,
                loginGateIpWhitelist: ipWhitelist,
                loginUrl,
                logoutUrl,
                resetNotifyEmail
            }
        });
    };

    const factorLabel = factor => {
        const key = `settings.factors.${factor}`;
        const label = t(key);
        return label === key ? factor : label;
    };

    const mainActions = [
        <Button key="save"
                size="big"
                color="accent"
                isDisabled={saving || loading}
                data-testid="extensions-global-save-btn"
                label={saving ? t('settings.saving') : t('settings.save')}
                onClick={save}/>
    ];

    return (
        <>
        {/* WCAG 2.2 SC 2.4.11 (Focus Appearance) + SC 1.4.11 (Non-text Contrast >= 3:1).
            #00538b on white yields ~7:1 contrast (AAA). The :focus-visible selector limits
            the ring to keyboard/switch navigation so mouse users are unaffected.
            Injected as a plain <style> element - this module uses inline styles by design
            and has no css-loader in its webpack config. */}
        <style>{'.mfa-admin-input:focus-visible{outline:2px solid #00538b;outline-offset:2px;}'}</style>
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('settings.title')} mainActions={mainActions}/>
                </div>
            )}
            content={(
                // ContentLayout's layers are flex:1/min-height:0 with no overflow, so tall content
                // (this full settings form) is clipped with no scrollbar. The OUTER div fills the
                // bounded-height paper and owns the vertical scroll full-width, so the scrollbar sits
                // at the window's right edge; the INNER div caps the readable content width.
                <div style={{flex: '1 1 0', minHeight: 0, overflowY: 'auto'}}>
                    <div style={{padding: '24px', maxWidth: 760, boxSizing: 'border-box'}}>
                    {loading ? <Loader/> : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('settings.description')}
                            </Typography>

                            <Typography variant="subheading" weight="bold" style={{display: 'block', margin: '8px 0 16px'}}>
                                {t('settings.enforcement.title')}
                            </Typography>
                            <Typography style={{display: 'block', marginBottom: 16, color: '#555'}}>
                                {t('settings.enforcement.help')}
                            </Typography>
                            {registeredFactors.length === 0 && (
                                <Typography style={{display: 'block', marginBottom: 16}} data-testid="no-factors">
                                    {t('settings.enforcement.noFactors')}
                                </Typography>
                            )}
                            {registeredFactors.map(factor => (
                                <CheckboxField key={factor}
                                               id={`enforce-${factor}`}
                                               testid={`enforce-${factor}-toggle`}
                                               checked={enforcedFactors.includes(factor)}
                                               label={factorLabel(factor)}
                                               help={t('settings.enforcement.factorHelp')}
                                               onChange={() => toggleFactor(factor)}/>
                            ))}

                            <TextField id="extensions-grace"
                                       testid="extensions-grace-input"
                                       type="number"
                                       value={graceDays}
                                       disabled={enforcedFactors.length === 0}
                                       min={0}
                                       max={365}
                                       label={t('settings.graceDays.label')}
                                       help={t('settings.graceDays.help')}
                                       onChange={v => setGraceDays(v)}/>

                            <Typography variant="subheading" weight="bold" style={{display: 'block', margin: '8px 0 16px'}}>
                                {t('settings.gate.title')}
                            </Typography>
                            <Typography style={{display: 'block', marginBottom: 16, color: '#555'}}>
                                {t('settings.gate.help')}
                            </Typography>

                            <CheckboxField id="extensions-gate-enabled"
                                           testid="extensions-gate-toggle"
                                           checked={gateEnabled}
                                           label={t('settings.gate.enabled.label')}
                                           help={t('settings.gate.enabled.help')}
                                           onChange={setGateEnabled}/>

                            <CheckboxField id="extensions-gate-trust-xff"
                                           testid="extensions-gate-trust-xff-toggle"
                                           checked={trustForwardedFor}
                                           label={t('settings.gate.trustForwardedFor.label')}
                                           help={t('settings.gate.trustForwardedFor.help')}
                                           onChange={setTrustForwardedFor}/>

                            <TextField id="extensions-gate-whitelist"
                                       testid="extensions-gate-whitelist-input"
                                       type="text"
                                       value={ipWhitelist}
                                       placeholder="203.0.113.7, 10.0.0.0/8"
                                       label={t('settings.gate.whitelist.label')}
                                       help={t('settings.gate.whitelist.help')}
                                       onChange={v => setIpWhitelist(v)}/>

                            <Typography variant="subheading" weight="bold" style={{display: 'block', margin: '8px 0 16px'}}>
                                {t('settings.urls.title')}
                            </Typography>
                            <Typography style={{display: 'block', marginBottom: 16, color: '#555'}}>
                                {t('settings.urls.help')}
                            </Typography>

                            <TextField id="extensions-login-url"
                                       testid="extensions-login-url-input"
                                       type="text"
                                       value={loginUrl}
                                       placeholder="/sites/mySite/login.html"
                                       label={t('settings.loginUrl.label')}
                                       help={t('settings.loginUrl.help')}
                                       onChange={v => setLoginUrl(v)}/>

                            <TextField id="extensions-logout-url"
                                       testid="extensions-logout-url-input"
                                       type="text"
                                       value={logoutUrl}
                                       placeholder="/sites/mySite/logout.html"
                                       label={t('settings.logoutUrl.label')}
                                       help={t('settings.logoutUrl.help')}
                                       onChange={v => setLogoutUrl(v)}/>

                            <Typography variant="subheading" weight="bold" style={{display: 'block', margin: '8px 0 16px'}}>
                                {t('settings.reset.title')}
                            </Typography>
                            <Typography style={{display: 'block', marginBottom: 16, color: '#555'}}>
                                {t('settings.reset.help')}
                            </Typography>

                            <TextField id="extensions-reset-notify-email"
                                       testid="extensions-reset-notify-email-input"
                                       type="text"
                                       value={resetNotifyEmail}
                                       placeholder="security@example.com, helpdesk@example.com"
                                       label={t('settings.resetNotifyEmail.label')}
                                       help={t('settings.resetNotifyEmail.help')}
                                       onChange={v => setResetNotifyEmail(v)}/>

                            {errorKey && (
                                <Typography role="alert"
                                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                                            data-testid="extensions-global-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography role="status"
                                            aria-live="polite"
                                            style={{color: '#006600', display: 'block', marginTop: 12}}
                                            data-testid="extensions-global-saved"
                                >
                                    {t('settings.saved')}
                                </Typography>
                            )}
                        </>
                    )}
                    </div>
                </div>
            )}
        />
        </>
    );
};

// Disabled fields are greyed via the control (cursor + #767676 label) rather than a wrapper
// opacity, so the help text keeps its #555 colour (7.46:1 on white) and the label stays at
// #767676 (4.54:1) - both above the WCAG AA/AAA threshold even when disabled.
const CheckboxField = ({id, testid, checked, disabled, label, help, onChange}) => (
    <div style={{marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 12}}>
        <input id={id}
               type="checkbox"
               checked={checked}
               disabled={disabled}
               data-testid={testid}
               aria-describedby={`${id}-help`}
               className="mfa-admin-input"
               style={{marginTop: 4, cursor: disabled ? 'not-allowed' : 'pointer'}}
               onChange={e => onChange(e.target.checked)}/>
        <div>
            <label htmlFor={id} style={{fontWeight: 600, display: 'block', color: disabled ? '#767676' : 'inherit', cursor: disabled ? 'not-allowed' : 'pointer'}}>
                {label}
            </label>
            <Typography id={`${id}-help`} variant="caption" style={{display: 'block', color: '#555'}}>{help}</Typography>
        </div>
    </div>
);

const TextField = ({id, testid, type, value, disabled, placeholder, label, help, min, max, onChange}) => (
    <div style={{marginBottom: 24}}>
        <label htmlFor={id} style={{fontWeight: 600, display: 'block', marginBottom: 4, color: disabled ? '#767676' : 'inherit'}}>{label}</label>
        <input id={id}
               type={type}
               value={value}
               disabled={disabled}
               placeholder={placeholder}
               min={min}
               max={max}
               data-testid={testid}
               aria-describedby={`${id}-help`}
               className="mfa-admin-input"
               style={{padding: '0.4rem', minWidth: 280, minHeight: 44, boxSizing: 'border-box',
                       borderRadius: 4, border: '1px solid #767676',
                       cursor: disabled ? 'not-allowed' : 'auto'}}
               onChange={e => onChange(e.target.value)}/>
        <Typography id={`${id}-help`} variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>{help}</Typography>
    </div>
);

export default GlobalSettings;
