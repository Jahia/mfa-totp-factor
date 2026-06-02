import React, {useEffect, useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Button, Input, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';
import {QRCodeCanvas} from 'qrcode.react';

const EnrollDialog = ({isOpen, enrollData, isLoading, errorKey, onCancel, onConfirm}) => {
    const {t} = useTranslation('mfa-totp-factor');
    const [code, setCode] = useState('');

    useEffect(() => {
        if (!isOpen) {
            setCode('');
        }
    }, [isOpen]);

    if (!isOpen || !enrollData) {
        return null;
    }

    return (
        <Modal isOpen={isOpen}
               size="medium"
               onOpenChange={open => {
 if (!open) {
 onCancel();
}
}}
        >
            <div>
                <ModalHeader title={t('enrollDialog.title')}/>
                <ModalBody>
                    <Typography>{t('enrollDialog.step1')}</Typography>
                    <div style={{textAlign: 'center', margin: '16px 0'}} data-testid="enroll-qr">
                        <QRCodeCanvas value={enrollData.otpauthUri} size={224} level="M"/>
                    </div>
                    <Typography variant="caption"
                                data-testid="enroll-secret"
                                style={{
                                    display: 'block',
                                    textAlign: 'center',
                                    fontFamily: 'monospace',
                                    wordBreak: 'break-all'
                                }}
                    >
                        {enrollData.secret}
                    </Typography>
                    <Typography style={{marginTop: 16, display: 'block'}}>{t('enrollDialog.step2')}</Typography>
                    <Input data-testid="enroll-code-input"
                           value={code}
                           maxLength={10}
                           placeholder="123456"
                           style={{marginTop: 8}}
                           onChange={e => setCode(e.target.value.replace(/\D/g, ''))}/>
                    {errorKey && (
                        <Typography style={{marginTop: 12, color: '#c00', display: 'block'}}
                                    data-testid="enroll-error"
                        >
                            {t(errorKey)}
                        </Typography>
                    )}
                </ModalBody>
                <ModalFooter>
                    <Button label={t('cancel')} onClick={onCancel}/>
                    <Button color="accent"
                            data-testid="enroll-confirm-btn"
                            label={t('confirm')}
                            isDisabled={isLoading || code.length < 6}
                            onClick={() => onConfirm(code)}/>
                </ModalFooter>
            </div>
        </Modal>
    );
};

EnrollDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    enrollData: PropTypes.shape({
        secret: PropTypes.string,
        otpauthUri: PropTypes.string,
        issuer: PropTypes.string,
        accountName: PropTypes.string
    }),
    isLoading: PropTypes.bool,
    errorKey: PropTypes.string,
    onCancel: PropTypes.func.isRequired,
    onConfirm: PropTypes.func.isRequired
};

export default EnrollDialog;
