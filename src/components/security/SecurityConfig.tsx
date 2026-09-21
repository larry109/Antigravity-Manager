import React, { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { request as invoke } from '../../utils/request';
import { Save, AlertTriangle, Shield, ShieldCheck, Network, Globe } from 'lucide-react';
import { showToast } from '../common/ToastContainer';

interface IpBlacklistConfig {
    enabled: boolean;
    block_message: string;
}

interface IpWhitelistConfig {
    enabled: boolean;
    whitelist_priority: boolean;
}

interface SecurityMonitorConfig {
    blacklist: IpBlacklistConfig;
    whitelist: IpWhitelistConfig;
    trusted_proxies: string[];
    cors_allowed_origins: string[];
}

/** Turn a textarea (one entry per line) into the list the backend expects. */
const linesToList = (raw: string): string[] =>
    raw.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

export const SecurityConfig: React.FC = () => {
    const { t } = useTranslation();
    const [config, setConfig] = useState<SecurityMonitorConfig | null>(null);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);

    useEffect(() => {
        loadConfig();
    }, []);

    const loadConfig = async () => {
        setLoading(true);
        try {
            const data = await invoke<SecurityMonitorConfig>('get_security_config');
            // Configs written by an older build carry neither field; normalise so the
            // controlled inputs below never receive undefined.
            setConfig({
                ...data,
                trusted_proxies: data.trusted_proxies ?? [],
                cors_allowed_origins: data.cors_allowed_origins ?? [],
            });
        } catch (e) {
            console.error('Failed to load security config', e);
            showToast(t('security.config.load_error'), 'error');
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        if (!config) return;
        setSaving(true);
        try {
            await invoke('update_security_config', { config });
            showToast(t('security.config.save_success'), 'success');
        } catch (e) {
            console.error('Failed to save security config', e);
            showToast(t('security.config.save_error'), 'error');
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return <div className="p-10 text-center"><span className="loading loading-spinner"></span></div>;
    }

    if (!config) {
        return <div className="p-10 text-center text-error">{t('security.config.load_error')}</div>;
    }

    return (
        <div className="p-6 max-w-4xl mx-auto space-y-8 h-full overflow-y-auto">
            <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold">{t('security.config.title')}</h2>
                <button
                    onClick={handleSave}
                    className="btn btn-primary gap-2"
                    disabled={saving}
                >
                    {saving ? <span className="loading loading-spinner loading-xs"></span> : <Save size={18} />}
                    {saving ? t('security.config.saving') : t('security.config.save')}
                </button>
            </div>

            {/* Blacklist Settings */}
            <div className="card bg-base-100 border border-gray-200 dark:border-base-300 shadow-sm">
                <div className="card-body">
                    <h3 className="card-title flex items-center gap-2 text-red-500">
                        <Shield size={24} />
                        {t('security.config.blacklist_title')}
                    </h3>
                    <p className="text-sm text-gray-500 mb-4">{t('security.config.blacklist_desc')}</p>

                    <div className="form-control">
                        <label className="label cursor-pointer justify-start gap-4">
                            <input
                                type="checkbox"
                                className="toggle toggle-error"
                                checked={config.blacklist.enabled}
                                onChange={(e) => setConfig({
                                    ...config,
                                    blacklist: { ...config.blacklist, enabled: e.target.checked }
                                })}
                            />
                            <span className="label-text font-medium">{t('security.config.enable_blacklist')}</span>
                        </label>
                    </div>

                    <div className="form-control w-full mt-4">
                        <label className="label">
                            <span className="label-text">{t('security.config.block_msg_label')}</span>
                        </label>
                        <input
                            type="text"
                            className="input input-bordered w-full"
                            value={config.blacklist.block_message}
                            onChange={(e) => setConfig({
                                ...config,
                                blacklist: { ...config.blacklist, block_message: e.target.value }
                            })}
                        />
                        <label className="label">
                            <span className="label-text-alt text-gray-400">{t('security.config.block_msg_desc')}</span>
                        </label>
                    </div>
                </div>
            </div>

            {/* Whitelist Settings */}
            <div className="card bg-base-100 border border-gray-200 dark:border-base-300 shadow-sm">
                <div className="card-body">
                    <h3 className="card-title flex items-center gap-2 text-green-500">
                        <ShieldCheck size={24} />
                        {t('security.config.whitelist_title')}
                    </h3>
                    <p className="text-sm text-gray-500 mb-4">{t('security.config.whitelist_desc')}</p>

                    <div className="form-control">
                        <label className="label cursor-pointer justify-start gap-4">
                            <input
                                type="checkbox"
                                className="toggle toggle-success"
                                checked={config.whitelist.enabled}
                                onChange={(e) => setConfig({
                                    ...config,
                                    whitelist: { ...config.whitelist, enabled: e.target.checked }
                                })}
                            />
                            <span className="label-text font-medium">{t('security.config.enable_whitelist')}</span>
                        </label>
                        <div className="text-xs text-gray-500 ml-14 mt-1 bg-yellow-50 dark:bg-yellow-900/20 p-2 rounded flex items-start gap-2">
                            <AlertTriangle size={14} className="mt-0.5 text-yellow-600 dark:text-yellow-400 shrink-0" />
                            {t('security.config.whitelist_warning')}
                        </div>
                    </div>

                    <div className="form-control mt-4">
                        <label className="label cursor-pointer justify-start gap-4">
                            <input
                                type="checkbox"
                                className="checkbox checkbox-success"
                                checked={config.whitelist.whitelist_priority}
                                disabled={!config.whitelist.enabled}
                                onChange={(e) => setConfig({
                                    ...config,
                                    whitelist: { ...config.whitelist, whitelist_priority: e.target.checked }
                                })}
                            />
                            <span className="label-text font-medium">{t('security.config.whitelist_priority')}</span>
                        </label>
                        <label className="label ml-8 pt-0">
                            <span className="label-text-alt text-gray-400">{t('security.config.whitelist_priority_desc')}</span>
                        </label>
                    </div>
                </div>
            </div>

            {/* Trusted reverse proxies */}
            <div className="card bg-base-100 border border-gray-200 dark:border-base-300 shadow-sm">
                <div className="card-body">
                    <h3 className="card-title flex items-center gap-2 text-blue-500">
                        <Network size={24} />
                        {t('security.config.trusted_proxies_title')}
                    </h3>
                    <p className="text-sm text-gray-500 mb-4">{t('security.config.trusted_proxies_desc')}</p>

                    <div className="form-control w-full">
                        <textarea
                            className="textarea textarea-bordered w-full font-mono text-sm"
                            rows={3}
                            spellCheck={false}
                            placeholder={"127.0.0.1\n::1"}
                            value={config.trusted_proxies.join('\n')}
                            onChange={(e) => setConfig({
                                ...config,
                                trusted_proxies: linesToList(e.target.value)
                            })}
                        />
                        <label className="label">
                            <span className="label-text-alt text-gray-400">{t('security.config.trusted_proxies_hint')}</span>
                        </label>
                    </div>

                    <div className="text-xs text-gray-500 bg-yellow-50 dark:bg-yellow-900/20 p-2 rounded flex items-start gap-2">
                        <AlertTriangle size={14} className="mt-0.5 text-yellow-600 dark:text-yellow-400 shrink-0" />
                        {t('security.config.trusted_proxies_warning')}
                    </div>
                </div>
            </div>

            {/* CORS origins */}
            <div className="card bg-base-100 border border-gray-200 dark:border-base-300 shadow-sm">
                <div className="card-body">
                    <h3 className="card-title flex items-center gap-2 text-purple-500">
                        <Globe size={24} />
                        {t('security.config.cors_title')}
                    </h3>
                    <p className="text-sm text-gray-500 mb-4">{t('security.config.cors_desc')}</p>

                    <div className="form-control w-full">
                        <textarea
                            className="textarea textarea-bordered w-full font-mono text-sm"
                            rows={3}
                            spellCheck={false}
                            placeholder={"https://chat.example.com"}
                            value={config.cors_allowed_origins.join('\n')}
                            onChange={(e) => setConfig({
                                ...config,
                                cors_allowed_origins: linesToList(e.target.value)
                            })}
                        />
                        <label className="label">
                            <span className="label-text-alt text-gray-400">{t('security.config.cors_hint')}</span>
                        </label>
                    </div>

                    {config.cors_allowed_origins.includes('*') && (
                        <div className="text-xs text-gray-500 bg-red-50 dark:bg-red-900/20 p-2 rounded flex items-start gap-2">
                            <AlertTriangle size={14} className="mt-0.5 text-red-600 dark:text-red-400 shrink-0" />
                            {t('security.config.cors_wildcard_warning')}
                        </div>
                    )}

                    <div className="text-xs text-gray-500 bg-blue-50 dark:bg-blue-900/20 p-2 rounded flex items-start gap-2">
                        <AlertTriangle size={14} className="mt-0.5 text-blue-600 dark:text-blue-400 shrink-0" />
                        {t('security.config.cors_restart_note')}
                    </div>
                </div>
            </div>
        </div>
    );
};
