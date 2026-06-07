import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useApolloClient} from '@apollo/client';
import {Button, Input, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';
import {StartRegistrationMutation, FinishRegistrationMutation} from '../MfaWebauthn.gql';
import {createCredential, isWebauthnSupported} from '../webauthnBrowser';

/**
 * Runs a WebAuthn registration ceremony: startRegistration → navigator.credentials.create →
 * finishRegistration. The browser prompts the user for their authenticator (fingerprint,
 * security key, platform passkey); the private key never leaves the authenticator.
 */
const RegisterDialog = ({isOpen, onClose, onRegistered}) => {
    const {t} = useTranslation('mfa-factors-webauthn');
    const client = useApolloClient();
    const [nickname, setNickname] = useState('');
    const [busy, setBusy] = useState(false);
    const [errorKey, setErrorKey] = useState(null);

    if (!isOpen) {
        return null;
    }

    const supported = isWebauthnSupported();

    const register = async () => {
        setBusy(true);
        setErrorKey(null);
        try {
            const start = await client.mutate({mutation: StartRegistrationMutation});
            const optionsJson = start?.data?.upa?.mfaFactors?.webauthn?.startRegistration?.publicKeyCredentialCreationOptions;
            if (!optionsJson) {
                throw new Error('no-options');
            }

            const responseJson = await createCredential(optionsJson);
            await client.mutate({
                mutation: FinishRegistrationMutation,
                variables: {response: responseJson, nickname: nickname.trim() || null}
            });
            setNickname('');
            onRegistered();
        } catch (e) {
            // NotAllowedError = user cancelled / timed out; everything else is a generic failure.
            setErrorKey(e && e.name === 'NotAllowedError' ? 'cancelled' : 'failed');
        } finally {
            setBusy(false);
        }
    };

    return (
        <Modal isOpen={isOpen}
               size="medium"
               onOpenChange={open => {
                   if (!open && !busy) {
                       onClose();
                   }
               }}
        >
            <div data-testid="webauthn-register-dialog">
                <ModalHeader title={t('register.title')}/>
                <ModalBody>
                    {supported ? (
                        <>
                            <Typography style={{display: 'block', marginBottom: 16}}>
                                {t('register.description')}
                            </Typography>
                            <label htmlFor="webauthn-nickname" style={{fontWeight: 600, display: 'block', marginBottom: 4}}>
                                {t('register.nicknameLabel')}
                            </label>
                            <Input id="webauthn-nickname"
                                   value={nickname}
                                   maxLength={60}
                                   placeholder={t('register.nicknamePlaceholder')}
                                   data-testid="webauthn-nickname-input"
                                   onChange={e => setNickname(e.target.value)}/>
                            {errorKey && (
                                <Typography role="alert"
                                            style={{color: '#a00000', display: 'block', marginTop: 12}}
                                            data-testid="webauthn-register-error"
                                >
                                    {t('errors.' + errorKey)}
                                </Typography>
                            )}
                        </>
                    ) : (
                        <Typography role="alert" style={{color: '#a00000', display: 'block'}} data-testid="webauthn-unsupported">
                            {t('errors.unsupported')}
                        </Typography>
                    )}
                </ModalBody>
                <ModalFooter>
                    <Button label={t('cancel')} isDisabled={busy} onClick={onClose}/>
                    <Button color="accent"
                            data-testid="webauthn-register-confirm"
                            label={busy ? t('register.inProgress') : t('register.button')}
                            isDisabled={busy || !supported}
                            onClick={register}/>
                </ModalFooter>
            </div>
        </Modal>
    );
};

export default RegisterDialog;
