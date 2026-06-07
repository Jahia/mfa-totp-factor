import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {SiteSettingsQuery, SetSiteSettingsMutation} from './SiteSettings.gql';
import {mapAdminError, resolveSiteKey} from './siteSettings.util';
import ResetUserSection from './ResetUserSection';

const SiteSettings = () => {
    const {t} = useTranslation('mfa-factors-totp');
    const siteKey = resolveSiteKey();

    const [enabled, setEnabled] = useState(false);
    const [groups, setGroups] = useState('');
    // Login/logout URLs are edited on the "MFA Community > Extensions" page; they are loaded and
    // round-tripped here unchanged because the mutation persists the full site settings state.
    const [loginUrl, setLoginUrl] = useState('');
    const [logoutUrl, setLogoutUrl] = useState('');
    const [savedAt, setSavedAt] = useState(null);
    const [errorKey, setErrorKey] = useState(null);

    const {data, loading} = useQuery(SiteSettingsQuery, {
        variables: {siteKey},
        skip: !siteKey,
        fetchPolicy: 'network-only'
    });

    useEffect(() => {
        const s = data && data.mfaTotp && data.mfaTotp.siteSettings;
        if (s) {
            setEnabled(Boolean(s.enabled));
            setGroups((s.enabledGroups || []).join(', '));
            setLoginUrl(s.loginUrl || '');
            setLogoutUrl(s.logoutUrl || '');
        }
    }, [data]);

    const [saveMutation, {loading: saving}] = useMutation(SetSiteSettingsMutation, {
        onCompleted: () => {
            setErrorKey(null);
            setSavedAt(Date.now());
        },
        onError: err => setErrorKey(mapAdminError(err))
    });

    const save = () => {
        setSavedAt(null);
        setErrorKey(null);
        const groupList = groups.split(',').map(g => g.trim()).filter(Boolean);
        saveMutation({
            variables: {
                siteKey,
                enabled,
                enabledGroups: enabled ? groupList : [],
                loginUrl: loginUrl.trim() || null,
                logoutUrl: logoutUrl.trim() || null
            }
        });
    };

    if (!siteKey) {
        return (
            <ContentLayout paper
                           content={
                               <div style={{padding: '24px'}}>
                                   <Typography>{t('siteSettings.noSite')}</Typography>
                               </div>
            }/>
        );
    }

    const mainActions = [
        <Button key="save"
                size="big"
                color="accent"
                isDisabled={saving || loading}
                data-testid="site-settings-save-btn"
                label={saving ? t('siteSettings.saving') : t('siteSettings.save')}
                onClick={save}/>
    ];

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('siteSettings.title', {siteKey})} mainActions={mainActions}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px', maxWidth: 760}}>
                    {loading ? <Loader/> : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('siteSettings.description')}
                            </Typography>

                            <CheckboxField id="totp-site-enabled"
                                           testid="site-enabled-toggle"
                                           checked={enabled}
                                           label={t('siteSettings.enabled.label')}
                                           help={t('siteSettings.enabled.help')}
                                           onChange={setEnabled}/>

                            <TextField id="totp-site-groups"
                                       testid="site-groups-input"
                                       type="text"
                                       value={groups}
                                       disabled={!enabled}
                                       placeholder="editors, reviewers"
                                       label={t('siteSettings.groups.label')}
                                       help={t('siteSettings.groups.help')}
                                       onChange={v => setGroups(v)}/>

                            {errorKey && (
                                <Typography role="alert"
                                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography role="status"
                                            aria-live="polite"
                                            style={{color: '#006600', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-saved"
                                >
                                    {t('siteSettings.saved')}
                                </Typography>
                            )}

                            <hr style={{margin: '32px 0'}}/>
                            <ResetUserSection siteKey={siteKey}/>
                        </>
                    )}
                </div>
            )}
        />
    );
};

const CheckboxField = ({id, testid, checked, disabled, label, help, onChange}) => (
    <div style={{marginBottom: 24, display: 'flex', alignItems: 'flex-start', gap: 12, opacity: disabled ? 0.5 : 1}}>
        <input id={id}
               type="checkbox"
               checked={checked}
               disabled={disabled}
               data-testid={testid}
               style={{marginTop: 4}}
               onChange={e => onChange(e.target.checked)}/>
        <div>
            <label htmlFor={id} style={{fontWeight: 600, display: 'block', cursor: disabled ? 'not-allowed' : 'pointer'}}>
                {label}
            </label>
            <Typography variant="caption" style={{display: 'block', color: '#555'}}>{help}</Typography>
        </div>
    </div>
);

const TextField = ({id, testid, type, value, disabled, placeholder, label, help, min, max, onChange}) => (
    <div style={{marginBottom: 24, opacity: disabled ? 0.5 : 1}}>
        <label htmlFor={id} style={{fontWeight: 600, display: 'block', marginBottom: 4}}>{label}</label>
        <input id={id}
               type={type}
               value={value}
               disabled={disabled}
               placeholder={placeholder}
               min={min}
               max={max}
               data-testid={testid}
               aria-describedby={`${id}-help`}
               style={{padding: '0.4rem', minWidth: 280, minHeight: 44, boxSizing: 'border-box',
                       borderRadius: 4, border: '1px solid #767676'}}
               onChange={e => onChange(e.target.value)}/>
        <Typography id={`${id}-help`} variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>{help}</Typography>
    </div>
);

export default SiteSettings;
