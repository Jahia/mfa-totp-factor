import React, {useState} from 'react';
import {useTranslation} from 'react-i18next';
import {useQuery, useMutation} from '@apollo/client';
import {Button, Header, Typography, Loader, Input, Modal, ModalHeader, ModalBody, ModalFooter} from '@jahia/moonstone';
import {ContentLayout} from '@jahia/moonstone-alpha';
import {StatusQuery, RenameCredentialMutation, DeleteCredentialMutation} from '../MfaWebauthn.gql';
import RegisterDialog from '../RegisterDialog/RegisterDialog';

const formatDate = ms => (ms ? new Date(Number(ms)).toLocaleString() : '—');

const MyWebauthnSettings = () => {
    const {t} = useTranslation('mfa-factors-webauthn');
    const [dialogOpen, setDialogOpen] = useState(false);
    const [renameTarget, setRenameTarget] = useState(null); // {credentialId, nickname}
    const [renameValue, setRenameValue] = useState('');
    const [deleteTarget, setDeleteTarget] = useState(null); // {credentialId, nickname}
    const {data, loading, refetch} = useQuery(StatusQuery, {fetchPolicy: 'network-only'});

    const [renameMutation, {loading: renaming}] = useMutation(RenameCredentialMutation);
    const [deleteMutation, {loading: deleting}] = useMutation(DeleteCredentialMutation);

    const credentials = (data && data.mfaWebauthn && data.mfaWebauthn.status &&
        data.mfaWebauthn.status.credentials) || [];

    const confirmRename = async () => {
        if (renameValue.trim()) {
            await renameMutation({variables: {credentialId: renameTarget.credentialId, nickname: renameValue.trim()}});
            setRenameTarget(null);
            refetch();
        }
    };

    const confirmDelete = async () => {
        await deleteMutation({variables: {credentialId: deleteTarget.credentialId}});
        setDeleteTarget(null);
        refetch();
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
                                            <th scope="col" style={{padding: '8px 4px'}}>{t('list.colName')}</th>
                                            <th scope="col" style={{padding: '8px 4px'}}>{t('list.colCreated')}</th>
                                            <th scope="col" style={{padding: '8px 4px'}}>{t('list.colLastUsed')}</th>
                                            <th scope="col" aria-label={t('list.colActions')} style={{padding: '8px 4px'}}/>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {credentials.map(c => (
                                            <tr key={c.credentialId} style={{borderBottom: '1px solid #eee'}}>
                                                <td style={{padding: '8px 4px'}}>{c.nickname}</td>
                                                <td style={{padding: '8px 4px'}}>{formatDate(c.createdAt)}</td>
                                                <td style={{padding: '8px 4px'}}>{formatDate(c.lastUsedAt)}</td>
                                                <td style={{padding: '8px 4px', textAlign: 'right'}}>
                                                    {/* size="big" keeps these row actions at the 44px AAA pointer-target size (WCAG 2.5.5). */}
                                                    <Button variant="ghost"
                                                            size="big"
                                                            label={t('list.rename')}
                                                            aria-label={t('list.renameOf', {nickname: c.nickname})}
                                                            onClick={() => {
                                                                setRenameValue(c.nickname || '');
                                                                setRenameTarget(c);
                                                            }}/>
                                                    <Button variant="ghost"
                                                            size="big"
                                                            color="danger"
                                                            label={t('list.delete')}
                                                            aria-label={t('list.deleteOf', {nickname: c.nickname})}
                                                            onClick={() => setDeleteTarget(c)}/>
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

                    {renameTarget && (
                        <Modal isOpen
                               size="medium"
                               onOpenChange={open => {
                                   if (!open && !renaming) {
                                       setRenameTarget(null);
                                   }
                               }}
                        >
                            <div data-testid="webauthn-rename-dialog">
                                <ModalHeader title={t('list.renameTitle')}/>
                                <ModalBody>
                                    <label htmlFor="webauthn-rename-input"
                                           style={{fontWeight: 600, display: 'block', marginBottom: 4}}
                                    >
                                        {t('list.renameLabel')}
                                    </label>
                                    <Input id="webauthn-rename-input"
                                           value={renameValue}
                                           maxLength={60}
                                           data-testid="webauthn-rename-input"
                                           onChange={e => setRenameValue(e.target.value)}/>
                                </ModalBody>
                                <ModalFooter>
                                    <Button label={t('cancel')} isDisabled={renaming} onClick={() => setRenameTarget(null)}/>
                                    <Button color="accent"
                                            data-testid="webauthn-rename-confirm"
                                            label={t('list.rename')}
                                            isDisabled={renaming || !renameValue.trim()}
                                            onClick={confirmRename}/>
                                </ModalFooter>
                            </div>
                        </Modal>
                    )}

                    {deleteTarget && (
                        <Modal isOpen
                               size="medium"
                               onOpenChange={open => {
                                   if (!open && !deleting) {
                                       setDeleteTarget(null);
                                   }
                               }}
                        >
                            <div data-testid="webauthn-delete-dialog" role="alertdialog">
                                <ModalHeader title={t('list.deleteTitle')}/>
                                <ModalBody>
                                    <Typography>{t('list.deleteConfirm', {nickname: deleteTarget.nickname})}</Typography>
                                </ModalBody>
                                <ModalFooter>
                                    <Button label={t('cancel')} isDisabled={deleting} onClick={() => setDeleteTarget(null)}/>
                                    <Button color="danger"
                                            data-testid="webauthn-delete-confirm"
                                            label={t('list.delete')}
                                            isDisabled={deleting}
                                            onClick={confirmDelete}/>
                                </ModalFooter>
                            </div>
                        </Modal>
                    )}
                </div>
            )}
        />
    );
};

export default MyWebauthnSettings;
