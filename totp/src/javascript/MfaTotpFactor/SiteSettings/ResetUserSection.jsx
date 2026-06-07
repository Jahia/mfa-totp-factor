import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useMutation} from '@apollo/client';
import {Button, Typography} from '@jahia/moonstone';
import {ResetUserMfaMutation} from './SiteSettings.gql';
import {mapAdminError} from './siteSettings.util';

/**
 * Admin recovery: clear a user's TOTP enrollment when they have lost their device AND their
 * backup codes. Distinct from self-service disable (which requires the user's own code).
 */
const ResetUserSection = ({siteKey}) => {
    const {t} = useTranslation('mfa-factors-totp');
    const [userId, setUserId] = useState('');
    const [confirming, setConfirming] = useState(false);
    const [done, setDone] = useState(false);
    const [errorKey, setErrorKey] = useState(null);

    const [resetMutation, {loading}] = useMutation(ResetUserMfaMutation, {
        onCompleted: () => {
            setDone(true);
            setErrorKey(null);
            setUserId('');
        },
        onError: err => {
            setDone(false);
            setErrorKey(mapAdminError(err));
        }
    });

    // Two-phase destructive action: the first click only ARMS the reset (shows the
    // irreversibility warning); the actual mutation requires a second, explicit click.
    const reset = () => {
        setConfirming(false);
        setDone(false);
        setErrorKey(null);
        resetMutation({variables: {userId: userId.trim(), siteKey}});
    };

    return (
        <section data-testid="reset-user-section">
            <Typography variant="heading" style={{display: 'block', marginBottom: 8}}>
                {t('siteSettings.reset.title')}
            </Typography>
            <Typography variant="caption" style={{display: 'block', color: '#555', marginBottom: 12}}>
                {t('siteSettings.reset.help')}
            </Typography>
            <div style={{display: 'flex', gap: 12, alignItems: 'center'}}>
                <input type="text"
                       value={userId}
                       placeholder={t('siteSettings.reset.placeholder')}
                       aria-label={t('siteSettings.reset.placeholder')}
                       data-testid="reset-user-input"
                       style={{padding: '0.4rem', minWidth: 240, minHeight: 44, boxSizing: 'border-box',
                               borderRadius: 4, border: '1px solid #767676'}}
                       onChange={e => {
                           setUserId(e.target.value);
                           setConfirming(false);
                       }}/>
                <Button color="danger"
                        data-testid="reset-user-btn"
                        isDisabled={loading || confirming || userId.trim() === ''}
                        label={t('siteSettings.reset.button')}
                        onClick={() => {
                            setDone(false);
                            setErrorKey(null);
                            setConfirming(true);
                        }}/>
            </div>
            {confirming && (
                <div role="alert"
                     data-testid="reset-user-confirm"
                     style={{marginTop: 12, padding: 12, border: '1px solid #a00000', borderRadius: 4, maxWidth: 560}}
                >
                    <Typography style={{display: 'block', marginBottom: 12}}>
                        {t('siteSettings.reset.confirmText', {userId: userId.trim()})}
                    </Typography>
                    <div style={{display: 'flex', gap: 12}}>
                        <Button color="danger"
                                data-testid="reset-user-confirm-btn"
                                isDisabled={loading}
                                label={t('siteSettings.reset.confirmButton')}
                                onClick={reset}/>
                        <Button data-testid="reset-user-cancel-btn"
                                label={t('siteSettings.reset.cancelButton')}
                                onClick={() => setConfirming(false)}/>
                    </div>
                </div>
            )}
            {done && (
                <Typography role="status"
                            aria-live="polite"
                            style={{color: '#006600', display: 'block', marginTop: 12}}
                            data-testid="reset-user-done"
                >
                    {t('siteSettings.reset.done')}
                </Typography>
            )}
            {errorKey && (
                <Typography role="alert"
                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                            data-testid="reset-user-error"
                >
                    {t(errorKey)}
                </Typography>
            )}
        </section>
    );
};

export default ResetUserSection;
