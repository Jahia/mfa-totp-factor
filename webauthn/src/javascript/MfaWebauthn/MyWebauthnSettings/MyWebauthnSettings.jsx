import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {StatusQuery, RenameCredentialMutation, DeleteCredentialMutation} from '../MfaWebauthn.gql';
import RegisterDialog from '../RegisterDialog/RegisterDialog';

const formatDate = ms => (ms ? new Date(Number(ms)).toLocaleString() : '—');

const MyWebauthnSettings = () => {
    const {t} = useTranslation('mfa-factors-webauthn');
    const [dialogOpen, setDialogOpen] = useState(false);
    const {data, loading, refetch} = useQuery(StatusQuery, {fetchPolicy: 'network-only'});

    const [renameMutation] = useMutation(RenameCredentialMutation);
    const [deleteMutation] = useMutation(DeleteCredentialMutation);

    const credentials = (data && data.mfaWebauthn && data.mfaWebauthn.status &&
        data.mfaWebauthn.status.credentials) || [];

    const onRename = async credentialId => {
        // eslint-disable-next-line no-alert
        const nickname = window.prompt(t('list.renamePrompt'));
        if (nickname && nickname.trim()) {
            await renameMutation({variables: {credentialId, nickname: nickname.trim()}});
            refetch();
        }
    };

    const onDelete = async (credentialId, nickname) => {
        // eslint-disable-next-line no-alert
        if (window.confirm(t('list.deleteConfirm', {nickname}))) {
            await deleteMutation({variables: {credentialId}});
            refetch();
        }
    };

    const mainActions = [
        <Button key="add"
                size="big"
                color="accent"
                data-testid="webauthn-add-btn"
                label={t('list.add')}
                onClick={() => setDialogOpen(true)}/>
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
                <div style={{padding: '24px', maxWidth: 760}}>
                    {loading ? <Loader/> : (
                        <>
                            <Typography style={{marginBottom: 24, display: 'block'}}>
                                {t('description')}
                            </Typography>

                            {credentials.length === 0 ? (
                                <Typography data-testid="webauthn-empty" style={{display: 'block', color: '#555'}}>
                                    {t('list.empty')}
                                </Typography>
                            ) : (
                                <table data-testid="webauthn-credentials" style={{width: '100%', borderCollapse: 'collapse'}}>
                                    <thead>
                                        <tr style={{textAlign: 'left', borderBottom: '1px solid #ccc'}}>
                                            <th style={{padding: '8px 4px'}}>{t('list.colName')}</th>
                                            <th style={{padding: '8px 4px'}}>{t('list.colCreated')}</th>
                                            <th style={{padding: '8px 4px'}}>{t('list.colLastUsed')}</th>
                                            <th style={{padding: '8px 4px'}}/>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {credentials.map(c => (
                                            <tr key={c.credentialId} style={{borderBottom: '1px solid #eee'}}>
                                                <td style={{padding: '8px 4px'}}>{c.nickname}</td>
                                                <td style={{padding: '8px 4px'}}>{formatDate(c.createdAt)}</td>
                                                <td style={{padding: '8px 4px'}}>{formatDate(c.lastUsedAt)}</td>
                                                <td style={{padding: '8px 4px', textAlign: 'right'}}>
                                                    <Button variant="ghost"
                                                            label={t('list.rename')}
                                                            onClick={() => onRename(c.credentialId)}/>
                                                    <Button variant="ghost"
                                                            color="danger"
                                                            label={t('list.delete')}
                                                            onClick={() => onDelete(c.credentialId, c.nickname)}/>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </>
                    )}
                    <RegisterDialog isOpen={dialogOpen}
                                    onClose={() => setDialogOpen(false)}
                                    onRegistered={() => {
                                        setDialogOpen(false);
                                        refetch();
                                    }}/>
                </div>
            )}
        />
    );
};

export default MyWebauthnSettings;
