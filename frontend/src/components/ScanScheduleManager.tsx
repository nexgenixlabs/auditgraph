import React, { useEffect, useState } from 'react';
import { api } from '../services/apiClient';

interface ScanSchedule {
  id: number;
  label: string;
  frequency: string;
  cron_expression: string;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  enabled: boolean;
  connection_label?: string;
  cloud?: string;
}

const FREQUENCIES = [
  { value: 'hourly', label: 'Every Hour' },
  { value: 'daily', label: 'Daily (2:00 AM UTC)' },
  { value: 'weekly', label: 'Weekly (Monday 2:00 AM)' },
  { value: 'monthly', label: 'Monthly (1st, 2:00 AM)' },
];

export default function ScanScheduleManager() {
  const [schedules, setSchedules] = useState<ScanSchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newLabel, setNewLabel] = useState('Default Schedule');
  const [newFrequency, setNewFrequency] = useState('daily');

  const fetchSchedules = () => {
    api.get<{ schedules: ScanSchedule[] }>('/scan-schedules')
      .then(d => setSchedules(d.schedules || []))
      .catch(() => setSchedules([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { fetchSchedules(); }, []);

  const createSchedule = () => {
    api.post('/scan-schedules', { label: newLabel, frequency: newFrequency })
      .then(() => { setShowCreate(false); fetchSchedules(); })
      .catch(() => {});
  };

  const toggleSchedule = (id: number, enabled: boolean) => {
    api.put(`/scan-schedules/${id}`, { enabled: !enabled })
      .then(() => fetchSchedules())
      .catch(() => {});
  };

  const deleteSchedule = (id: number) => {
    if (!window.confirm('Delete this snapshot schedule?')) return;
    api.del(`/scan-schedules/${id}`)
      .then(() => fetchSchedules())
      .catch(() => {});
  };

  if (loading) return <div className="text-gray-500 text-sm py-4">Loading snapshot schedules...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-200">Snapshot Schedules</h3>
          <p className="text-xs text-gray-500 mt-0.5">Configure automated snapshot intervals</p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-3 py-1.5 bg-blue-600 text-white text-xs rounded-lg hover:bg-blue-700 transition"
        >
          + Add Schedule
        </button>
      </div>

      {showCreate && (
        <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 space-y-3">
          <div>
            <label className="block text-xs text-gray-400 mb-1">Label</label>
            <input
              value={newLabel}
              onChange={e => setNewLabel(e.target.value)}
              className="w-full px-3 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-white"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Frequency</label>
            <select
              value={newFrequency}
              onChange={e => setNewFrequency(e.target.value)}
              className="w-full px-3 py-1.5 bg-gray-800 border border-gray-600 rounded text-sm text-white"
            >
              {FREQUENCIES.map(f => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button onClick={createSchedule} className="px-3 py-1.5 bg-blue-600 text-white text-xs rounded hover:bg-blue-700">
              Create
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 bg-gray-700 text-gray-300 text-xs rounded hover:bg-gray-600">
              Cancel
            </button>
          </div>
        </div>
      )}

      {schedules.length === 0 ? (
        <div className="text-center py-8 text-gray-500 text-sm">
          No snapshot schedules configured. Add one to automate snapshots.
        </div>
      ) : (
        <div className="space-y-2">
          {schedules.map(s => (
            <div key={s.id} className="flex items-center justify-between bg-gray-800/50 border border-gray-700 rounded-lg px-4 py-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => toggleSchedule(s.id, s.enabled)}
                  className={`w-8 h-4 rounded-full relative transition ${s.enabled ? 'bg-blue-600' : 'bg-gray-600'}`}
                >
                  <div className={`absolute top-0.5 w-3 h-3 bg-white rounded-full transition-transform ${s.enabled ? 'left-4' : 'left-0.5'}`} />
                </button>
                <div>
                  <div className="text-sm text-white font-medium">{s.label}</div>
                  <div className="text-xs text-gray-500">
                    {FREQUENCIES.find(f => f.value === s.frequency)?.label || s.frequency}
                    {s.connection_label && ` · ${s.connection_label}`}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  {s.next_run_at && (
                    <div className="text-[10px] text-gray-500">
                      Next: {new Date(s.next_run_at).toLocaleString()}
                    </div>
                  )}
                  {s.last_run_at && (
                    <div className="text-[10px] text-gray-500">
                      Last: {new Date(s.last_run_at).toLocaleString()}
                      {s.last_run_status && (
                        <span className={`ml-1 ${s.last_run_status === 'completed' ? 'text-green-400' : 'text-red-400'}`}>
                          ({s.last_run_status})
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => deleteSchedule(s.id)}
                  className="text-gray-500 hover:text-red-400 transition"
                  title="Delete schedule"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
