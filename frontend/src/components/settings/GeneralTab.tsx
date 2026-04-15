import React from 'react';
import { ACCOUNT_TIER_LABELS, getTermLabel, getTermDiscount } from '../../constants/pricing';
import type { SettingsData } from './types';
import { TIME_MS } from '../../constants/metrics';

export interface GeneralTabProps {
  settings: SettingsData;
  update: (key: keyof SettingsData, value: string) => void;
  currentOrg: any;
  setError: (error: string) => void;
  setSuccess: (msg: string) => void;
  currentPassword: string;
  setCurrentPassword: (v: string) => void;
  newPassword: string;
  setNewPassword: (v: string) => void;
  confirmPassword: string;
  setConfirmPassword: (v: string) => void;
  pwChanging: boolean;
  pwMessage: { type: 'success' | 'error'; text: string } | null;
  setPwMessage: (v: { type: 'success' | 'error'; text: string } | null) => void;
  handleChangePassword: () => void;
}

export function GeneralTab({
  settings,
  update,
  currentOrg,
  setError,
  setSuccess,
  currentPassword,
  setCurrentPassword,
  newPassword,
  setNewPassword,
  confirmPassword,
  setConfirmPassword,
  pwChanging,
  pwMessage,
  setPwMessage,
  handleChangePassword,
}: GeneralTabProps) {
  return (
    <>
      {/* Section 1: Organization */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-5">
        <div className="text-lg font-semibold text-gray-900">Organization</div>

        <div className="grid grid-cols-2 gap-6">
          {/* Left: Logo upload */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Organization Logo</label>
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-gray-400 transition">
              {currentOrg?.settings?.logo_url ? (
                <img src={String(currentOrg.settings.logo_url)} alt="Logo" className="w-16 h-16 mx-auto mb-2 rounded-lg object-cover" />
              ) : (
                <svg className="w-12 h-12 mx-auto text-gray-300 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              )}
              <p className="text-xs text-gray-500">Drag & drop or click to upload</p>
              <p className="text-[10px] text-gray-400 mt-1">PNG, SVG, or JPG — max 2MB</p>
              <input
                type="file"
                accept="image/png,image/jpeg,image/svg+xml"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  if (file.size > 2 * 1024 * 1024) { setError('Logo must be under 2MB'); return; }
                  const reader = new FileReader();
                  reader.onload = async () => {
                    try {
                      const tid = currentOrg?.id;
                      if (!tid) { setError('No organization context'); return; }
                      // Parse data URL into base64 + content_type for backend
                      const dataUrl = reader.result as string;
                      const match = dataUrl.match(/^data:(image\/[^;]+);base64,(.+)$/);
                      if (!match) { setError('Invalid image format'); return; }
                      const [, content_type, logo_data] = match;
                      const res = await fetch(`/api/clients/${tid}/logo`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ logo_data, content_type }),
                      });
                      if (!res.ok) {
                        const err = await res.json().catch(() => ({}));
                        throw new Error(err.error || 'Upload failed');
                      }
                      setSuccess('Logo uploaded');
                    } catch (err) { setError(err instanceof Error ? err.message : 'Failed to upload logo'); }
                  };
                  reader.readAsDataURL(file);
                }}
                className="hidden"
                id="logo-upload"
              />
              <label htmlFor="logo-upload" className="mt-2 inline-block px-3 py-1.5 bg-gray-100 text-gray-700 text-xs font-medium rounded-lg hover:bg-gray-200 cursor-pointer transition">
                Choose File
              </label>
            </div>
          </div>

          {/* Right: Org Name + Timezone + Theme */}
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Organization Name</label>
              <input
                type="text"
                value={settings.org_name}
                onChange={e => update('org_name', e.target.value)}
                placeholder="e.g., Acme Corp"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
              <p className="text-xs text-gray-400 mt-1">Appears on PDF reports and email notifications</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Timezone</label>
              <select
                value={settings.timezone || 'UTC'}
                onChange={e => update('timezone' as keyof SettingsData, e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="UTC">UTC</option>
                <option value="America/New_York">Eastern (ET)</option>
                <option value="America/Chicago">Central (CT)</option>
                <option value="America/Denver">Mountain (MT)</option>
                <option value="America/Los_Angeles">Pacific (PT)</option>
                <option value="Europe/London">London (GMT)</option>
                <option value="Europe/Berlin">Berlin (CET)</option>
                <option value="Asia/Tokyo">Tokyo (JST)</option>
                <option value="Asia/Kolkata">India (IST)</option>
                <option value="Australia/Sydney">Sydney (AEST)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Theme</label>
              <div className="flex gap-2">
                {(['light', 'dark', 'system'] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => update('theme' as keyof SettingsData, t)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium border transition capitalize ${
                      settings.theme === t
                        ? 'bg-blue-600 text-white border-blue-600'
                        : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Subscription Info */}
        {currentOrg && (
          <div className="pt-3 border-t space-y-3">
            <div className="text-sm font-semibold text-gray-800">Plan</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Plan</div>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                  (ACCOUNT_TIER_LABELS[currentOrg.plan] || ACCOUNT_TIER_LABELS.free).bg
                } ${(ACCOUNT_TIER_LABELS[currentOrg.plan] || ACCOUNT_TIER_LABELS.free).color}`}>
                  {(ACCOUNT_TIER_LABELS[currentOrg.plan] || ACCOUNT_TIER_LABELS.free).label}
                </span>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Term</div>
                <div className="text-sm font-semibold text-gray-800">
                  {getTermLabel(currentOrg.subscription_term || 0)}
                  {getTermDiscount(currentOrg.subscription_term || 0) > 0 && (
                    <span className="ml-1 text-[10px] text-green-600 font-semibold">{getTermDiscount(currentOrg.subscription_term || 0) * 100}% off</span>
                  )}
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Activated</div>
                <div className="text-sm font-semibold text-gray-800">
                  {currentOrg.license_activated_at
                    ? new Date(currentOrg.license_activated_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                    : '\u2014'}
                </div>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Expires</div>
                <div className={`text-sm font-semibold ${
                  currentOrg.license_expires_at
                    ? (new Date(currentOrg.license_expires_at).getTime() - Date.now()) / TIME_MS.DAY < 30
                      ? 'text-yellow-600'
                      : (new Date(currentOrg.license_expires_at).getTime() - Date.now()) < 0
                        ? 'text-red-600'
                        : 'text-gray-800'
                    : 'text-gray-400'
                }`}>
                  {currentOrg.license_expires_at
                    ? new Date(currentOrg.license_expires_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                    : currentOrg.subscription_term === 0 ? 'Monthly (no expiry)' : '\u2014'}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Change Password */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">Change Password</div>
          <p className="text-sm text-gray-500 mt-0.5">Update your account password</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-2xl">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={e => { setCurrentPassword(e.target.value); setPwMessage(null); }}
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Enter current password"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={e => { setNewPassword(e.target.value); setPwMessage(null); }}
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Min. 8 characters"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={e => { setConfirmPassword(e.target.value); setPwMessage(null); }}
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              placeholder="Repeat new password"
            />
          </div>
        </div>
        {pwMessage && (
          <div className={`text-sm px-3 py-2 rounded-lg ${pwMessage.type === 'success' ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
            {pwMessage.text}
          </div>
        )}
        <button
          onClick={handleChangePassword}
          disabled={pwChanging || !currentPassword || !newPassword || !confirmPassword}
          className="px-4 py-2 rounded-lg text-sm font-medium bg-blue-600 text-white hover:bg-blue-700 transition disabled:opacity-50"
        >
          {pwChanging ? 'Changing...' : 'Change Password'}
        </button>
      </div>
    </>
  );
}
