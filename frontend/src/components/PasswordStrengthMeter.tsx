import React, { useMemo } from 'react';

interface Props {
  password: string;
}

function getStrength(pw: string): { score: number; label: string; color: string; checks: { label: string; met: boolean }[] } {
  const checks = [
    { label: '12+ characters', met: pw.length >= 12 },
    { label: 'Uppercase letter', met: /[A-Z]/.test(pw) },
    { label: 'Lowercase letter', met: /[a-z]/.test(pw) },
    { label: 'Number', met: /\d/.test(pw) },
    { label: 'Special character', met: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]/.test(pw) },
  ];

  const score = checks.filter(c => c.met).length;

  if (score <= 1) return { score, label: 'Very Weak', color: 'bg-red-500', checks };
  if (score <= 2) return { score, label: 'Weak', color: 'bg-orange-500', checks };
  if (score <= 3) return { score, label: 'Fair', color: 'bg-yellow-500', checks };
  if (score <= 4) return { score, label: 'Strong', color: 'bg-blue-500', checks };
  return { score, label: 'Very Strong', color: 'bg-green-500', checks };
}

export default function PasswordStrengthMeter({ password }: Props) {
  const strength = useMemo(() => getStrength(password), [password]);

  if (!password) return null;

  return (
    <div className="mt-2 space-y-2">
      {/* Strength bar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden flex gap-0.5">
          {[1, 2, 3, 4, 5].map(i => (
            <div
              key={i}
              className={`flex-1 rounded-full transition-colors ${
                i <= strength.score ? strength.color : 'bg-gray-700'
              }`}
            />
          ))}
        </div>
        <span className={`text-[10px] font-medium ${
          strength.score <= 2 ? 'text-red-400' :
          strength.score <= 3 ? 'text-yellow-400' :
          strength.score <= 4 ? 'text-blue-400' : 'text-green-400'
        }`}>
          {strength.label}
        </span>
      </div>

      {/* Requirement checklist */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
        {strength.checks.map(check => (
          <div key={check.label} className="flex items-center gap-1.5 text-[10px]">
            <span className={check.met ? 'text-green-400' : 'text-gray-600'}>
              {check.met ? '✓' : '○'}
            </span>
            <span className={check.met ? 'text-gray-300' : 'text-gray-600'}>
              {check.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
