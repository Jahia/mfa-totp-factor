import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Chip, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {
    StatusQuery,
    EnrollMutation,
    ConfirmEnrollMutation,
    DisableMutation,
    RegenerateBackupCodesMutation
} from '../MfaTotpFactor.gql';
import EnrollDialog from '../EnrollDialog/EnrollDialog';
import CodePromptDialog from '../CodePromptDialog/CodePromptDialog';
import BackupCodesDialog from '../BackupCodesDialog/BackupCodesDialog';

const mapError = err => {
    const gql = err && err.graphQLErrors && err.graphQLErrors[0];
    const msg = (gql && gql.message) || (err && err.message) || 'unknown_error';
    if (msg.indexOf('invalid_code') !== -1) {
        return 'errors.invalidCode';
    }

    if (msg.indexOf('locked_out') !== -1) {
        return 'errors.lockedOut';
    }

    if (msg.indexOf('already_enrolled') !== -1) {
        return 'errors.alreadyEnrolled';
    }

    if (msg.indexOf('not_enrolled') !== -1) {
        return 'errors.notEnrolled';
    }

    return 'errors.generic';
};

const MyMfaSettings = () => {
    const {t} = useTranslation('mfa-factors-totp');

    const [enrollOpen, setEnrollOpen] = useState(false);
    const [enrollData, setEnrollData] = useState(null);
    const [disableOpen, setDisableOpen] = useState(false);
    const [regenOpen, setRegenOpen] = useState(false);
    const [backupCodes, setBackupCodes] = useState(null);
    const [errorKey, setErrorKey] = useState(null);

    const {data, loading, refetch} = useQuery(StatusQuery, {fetchPolicy: 'network-only'});

    const status = data && data.mfaTotp && data.mfaTotp.status;
    const isEnrolled = Boolean(status && status.enrolled);

    const [enrollMutation, {loading: enrollLoading}] = useMutation(EnrollMutation, {
        onCompleted: res => {
            setEnrollData(res.upa.mfaFactors.totp.enroll);
            setErrorKey(null);
            setEnrollOpen(true);
        },
        onError: err => setErrorKey(mapError(err))
    });

    const [confirmMutation, {loading: confirmLoading}] = useMutation(ConfirmEnrollMutation, {
        onCompleted: res => {
            setEnrollData(null);
            setEnrollOpen(false);
            setBackupCodes(res.upa.mfaFactors.totp.confirmEnroll.backupCodes);
            setErrorKey(null);
            refetch();
        },
        onError: err => setErrorKey(mapError(err))
    });

    const [disableMutation, {loading: disableLoading}] = useMutation(DisableMutation, {
        refetchQueries: [{query: StatusQuery}],
        awaitRefetchQueries: true,
        onCompleted: () => {
            setDisableOpen(false);
            setErrorKey(null);
        },
        onError: err => setErrorKey(mapError(err))
    });

    const [regenMutation, {loading: regenLoading}] = useMutation(RegenerateBackupCodesMutation, {
        onCompleted: res => {
            setRegenOpen(false);
            setBackupCodes(res.upa.mfaFactors.totp.regenerateBackupCodes.backupCodes);
            setErrorKey(null);
            refetch();
        },
        onError: err => setErrorKey(mapError(err))
    });

    const startEnroll = () => {
        setErrorKey(null);
        enrollMutation({variables: {force: false}});
    };

    const openRegen = () => {
        setErrorKey(null);
        setRegenOpen(true);
    };

    const openDisable = () => {
        setErrorKey(null);
        setDisableOpen(true);
    };

    const closeEnroll = () => {
        setEnrollOpen(false);
        setEnrollData(null);
        setErrorKey(null);
    };

    const mainActions = isEnrolled ? [
        <Button key="regen"
                size="big"
                data-testid="regen-backup-btn"
                label={t('regenerateBackupCodes')}
                onClick={openRegen}/>,
        <Button key="disable"
                size="big"
                color="danger"
                data-testid="disable-mfa-btn"
                label={t('disable')}
                onClick={openDisable}/>
    ] : [
        <Button key="enable"
                size="big"
                color="accent"
                isDisabled={enrollLoading}
                data-testid="enable-mfa-btn"
                label={t('enable')}
                onClick={startEnroll}/>
    ];

    return (
        <ContentLayout
            paper
            header={(
                <div style={{backgroundColor: 'white'}}>
                    <Header title={t('title')} mainActions={mainActions}/>
                </div>
            )}
            content={(
                <div style={{padding: '24px'}}>
                    {loading ? (
                        <Loader/>
                    ) : (
                        <>
                            <Typography variant="heading" data-testid="mfa-status">
                                {t('status')}{' '}
                                <Chip color={isEnrolled ? 'accent' : 'default'}
                                      label={isEnrolled ? t('enabled') : t('disabled')}/>
                            </Typography>
                            <Typography style={{marginTop: 16, maxWidth: 720, display: 'block'}}>
                                {isEnrolled ?
                                    t('descriptionEnabled', {count: (status && status.remainingBackupCodes) || 0}) :
                                    t('descriptionDisabled')}
                            </Typography>
                            {errorKey && (
                                <Typography style={{marginTop: 16, color: '#c00', display: 'block'}}
                                            data-testid="mfa-error"
                                >
                                    {t(errorKey)}
                                </Typography>
                            )}
                        </>
                    )}

                    <EnrollDialog
                        isOpen={enrollOpen}
                        enrollData={enrollData}
                        isLoading={confirmLoading}
                        errorKey={errorKey}
                        onCancel={closeEnroll}
                        onConfirm={code => confirmMutation({variables: {code}})}
                    />

                    <CodePromptDialog
                        isOpen={disableOpen}
                        title={t('disableDialog.title')}
                        description={t('disableDialog.description')}
                        acceptLabel={t('disable')}
                        acceptColor="danger"
                        isLoading={disableLoading}
                        errorKey={errorKey}
                        onCancel={() => setDisableOpen(false)}
                        onAccept={code => disableMutation({variables: {code}})}
                    />

                    <CodePromptDialog
                        isOpen={regenOpen}
                        title={t('regenDialog.title')}
                        description={t('regenDialog.description')}
                        acceptLabel={t('regenerate')}
                        isLoading={regenLoading}
                        errorKey={errorKey}
                        onCancel={() => setRegenOpen(false)}
                        onAccept={code => regenMutation({variables: {code}})}
                    />

                    <BackupCodesDialog
                        isOpen={Boolean(backupCodes)}
                        codes={backupCodes || []}
                        onClose={() => setBackupCodes(null)}
                    />
                </div>
            )}
        />
    );
};

export default MyMfaSettings;
