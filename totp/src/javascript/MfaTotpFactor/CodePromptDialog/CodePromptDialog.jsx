import React, {useEffect, useState} from 'react';
import PropTypes from 'prop-types';
import {useTranslation} from 'react-i18next';
import {Button, Input, Typography, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';

const CodePromptDialog = ({
    isOpen, title, description, acceptLabel, acceptColor,
    isLoading, errorKey, onCancel, onAccept
}) => {
    const {t} = useTranslation('mfa-factors-totp');
    const [code, setCode] = useState('');

    useEffect(() => {
        if (!isOpen) {
            setCode('');
        }
    }, [isOpen]);

    if (!isOpen) {
        return null;
    }

    return (
        <Modal isOpen={isOpen}
               size="small"
               onOpenChange={open => {
 if (!open) {
 onCancel();
}
}}
        >
            <div>
                <ModalHeader title={title}/>
                <ModalBody>
                    <Typography>{description}</Typography>
                    <Input data-testid="code-prompt-input"
                           value={code}
                           maxLength={10}
                           placeholder="123456"
                           aria-label={description}
                           style={{marginTop: 12}}
                           onChange={e => setCode(e.target.value.replace(/[^A-Za-z0-9-]/g, ''))}/>
                    {errorKey && (
                        <Typography role="alert"
                                    style={{marginTop: 12, color: '#a00000', display: 'block'}}
                                    data-testid="code-prompt-error"
                        >
                            {t(errorKey)}
                        </Typography>
                    )}
                </ModalBody>
                <ModalFooter>
                    <Button label={t('cancel')} onClick={onCancel}/>
                    <Button color={acceptColor || 'accent'}
                            data-testid="code-prompt-accept-btn"
                            label={acceptLabel}
                            isDisabled={isLoading || code.length < 6}
                            onClick={() => onAccept(code)}/>
                </ModalFooter>
            </div>
        </Modal>
    );
};

CodePromptDialog.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    title: PropTypes.string.isRequired,
    description: PropTypes.string.isRequired,
    acceptLabel: PropTypes.string.isRequired,
    acceptColor: PropTypes.string,
    isLoading: PropTypes.bool,
    errorKey: PropTypes.string,
    onCancel: PropTypes.func.isRequired,
    onAccept: PropTypes.func.isRequired
};

export default CodePromptDialog;
