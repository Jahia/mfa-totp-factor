import React, {useEffect, useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {SiteSettingsQuery, SetSiteSettingsMutation} from './SiteSettings.gql';
import {mapAdminError, resolveSiteKey} from './siteSettings.util';
import ResetUserSection from './ResetUserSection';
import AuditReportSection from './AuditReportSection';

const SiteSettings = () => {
    const {t} = useTranslation('mfa-totp-factor');
    const siteKey = resolveSiteKey();

    const [enabled, setEnabled] = useState(false);
    const [enforced, setEnforced] = useState(false);
    const [graceDays, setGraceDays] = useState(0);
    const [groups, setGroups] = useState('');
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
            setEnforced(Boolean(s.enforced));
            setGraceDays(Number(s.graceDays) || 0);
            setGroups((s.enabledGroups || []).join(', '));
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
                enforced: enabled ? enforced : false,
                graceDays: enabled && enforced ? Math.max(0, Number(graceDays) || 0) : 0,
                enabledGroups: enabled ? groupList : []
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
                label={t('siteSettings.save')}
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

                            <CheckboxField id="totp-site-enforced"
                                           testid="site-enforced-toggle"
                                           checked={enabled && enforced}
                                           disabled={!enabled}
                                           label={t('siteSettings.enforced.label')}
                                           help={t('siteSettings.enforced.help')}
                                           onChange={setEnforced}/>

                            <TextField id="totp-site-grace"
                                       testid="site-grace-input"
                                       type="number"
                                       value={graceDays}
                                       disabled={!enabled || !enforced}
                                       label={t('siteSettings.graceDays.label')}
                                       help={t('siteSettings.graceDays.help')}
                                       onChange={v => setGraceDays(v)}/>

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
                                <Typography style={{color: '#c00', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                            {savedAt && !errorKey && (
                                <Typography style={{color: '#080', display: 'block', marginTop: 12}}
                                            data-testid="site-settings-saved"
                                >
                                    {t('siteSettings.saved')}
                                </Typography>
                            )}

                            <hr style={{margin: '32px 0'}}/>
                            <ResetUserSection siteKey={siteKey}/>

                            <hr style={{margin: '32px 0'}}/>
                            <AuditReportSection siteKey={siteKey}/>
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

const TextField = ({id, testid, type, value, disabled, placeholder, label, help, onChange}) => (
    <div style={{marginBottom: 24, opacity: disabled ? 0.5 : 1}}>
        <label htmlFor={id} style={{fontWeight: 600, display: 'block', marginBottom: 4}}>{label}</label>
        <input id={id}
               type={type}
               value={value}
               disabled={disabled}
               placeholder={placeholder}
               data-testid={testid}
               style={{padding: '0.4rem', minWidth: 280, borderRadius: 4, border: '1px solid #ccc'}}
               onChange={e => onChange(e.target.value)}/>
        <Typography variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>{help}</Typography>
    </div>
);

export default SiteSettings;
