import React from 'react';
import {useTranslation} from 'react-i18next';
import {useLazyQuery} from '@apollo/client';
import {Button, Typography} from '@jahia/moonstone';
import {AuditEventsQuery, EnrollmentReportQuery} from './SiteSettings.gql';

const formatTs = ts => {
    if (!ts) {
        return '';
    }

    const d = new Date(Number(ts));
    return Number.isNaN(d.getTime()) ? String(ts) : d.toISOString().replace('T', ' ').slice(0, 19);
};

/**
 * Admin reporting: a recent-audit-events table and an enrollment summary
 * ("who hasn't enrolled?"). Both load lazily on demand to avoid scanning on every page view.
 */
const AuditReportSection = ({siteKey}) => {
    const {t} = useTranslation('mfa-factors-webauthn');

    const [loadAudit, audit] = useLazyQuery(AuditEventsQuery, {
        variables: {siteKey, limit: 50},
        fetchPolicy: 'network-only'
    });
    const [loadReport, report] = useLazyQuery(EnrollmentReportQuery, {
        variables: {siteKey, limit: 200},
        fetchPolicy: 'network-only'
    });

    const events = (audit.data && audit.data.mfaWebauthn && audit.data.mfaWebauthn.auditEvents) || [];
    const reportData = report.data && report.data.mfaWebauthn && report.data.mfaWebauthn.enrollmentReport;

    return (
        <section data-testid="audit-report-section">
            <Typography variant="heading" style={{display: 'block', marginBottom: 12}}>
                {t('siteSettings.audit.title')}
            </Typography>

            <div style={{display: 'flex', gap: 12, marginBottom: 16}}>
                <Button data-testid="load-audit-btn"
                        isDisabled={audit.loading}
                        label={t('siteSettings.audit.loadEvents')}
                        onClick={() => loadAudit()}/>
                <Button data-testid="load-report-btn"
                        isDisabled={report.loading}
                        label={t('siteSettings.audit.loadReport')}
                        onClick={() => loadReport()}/>
            </div>

            {reportData && (
                <div data-testid="enrollment-report" style={{marginBottom: 24}}>
                    <Typography style={{display: 'block'}}>
                        {t('siteSettings.audit.reportSummary', {
                            registered: reportData.registeredUsers,
                            total: reportData.totalUsers
                        })}
                    </Typography>
                    {reportData.notRegistered.length > 0 && (
                        <Typography variant="caption" style={{display: 'block', color: '#555', marginTop: 4}}>
                            {t('siteSettings.audit.notRegistered')}: {reportData.notRegistered.join(', ')}
                            {reportData.truncated ? ' …' : ''}
                        </Typography>
                    )}
                </div>
            )}

            {events.length > 0 && (
                <table data-testid="audit-table" style={{borderCollapse: 'collapse', width: '100%'}}>
                    <thead>
                        <tr>
                            <th style={cell}>{t('siteSettings.audit.colTime')}</th>
                            <th style={cell}>{t('siteSettings.audit.colEvent')}</th>
                            <th style={cell}>{t('siteSettings.audit.colOutcome')}</th>
                            <th style={cell}>{t('siteSettings.audit.colUser')}</th>
                            <th style={cell}>{t('siteSettings.audit.colDetail')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {events.map(e => (
                            <tr key={`${e.timestamp}-${e.eventType}-${e.userId}-${e.detail}`}>
                                <td style={cell}>{formatTs(e.timestamp)}</td>
                                <td style={cell}>{e.eventType}</td>
                                <td style={cell}>{e.outcome}</td>
                                <td style={cell}>{e.userId}</td>
                                <td style={cell}>{e.detail}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </section>
    );
};

const cell = {border: '1px solid #e0e0e0', padding: '4px 8px', textAlign: 'left', fontSize: '0.85rem'};

export default AuditReportSection;
