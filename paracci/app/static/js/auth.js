/**
 * Paracci Auth / Unlock Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    const MIN_LENGTH = 12;
    const MAX_LENGTH = 128;
    const MIN_UNIQUE = 5;
    const MIN_ENTROPY = 64;
    const NUMERIC_MIN_LENGTH = 20;
    const SEQUENCE_ROWS = [
        '01234567890123456789',
        'abcdefghijklmnopqrstuvwxyz',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ];
    const COMMON_WEAK = new Set([
        'password',
        'password1',
        'password12',
        'password123',
        'password1234',
        'passphrase',
        'letmein',
        'welcome',
        'admin',
        'administrator',
        'paracci',
        'qwerty',
        'qwerty123',
        'iloveyou'
    ]);

    const authForm = document.getElementById('authForm');
    const submitBtn = document.getElementById('submitBtn');
    const pinInput = document.getElementById('pinInput');
    const pinDots = document.querySelectorAll('.pin-dot');
    const pinDisplay = document.getElementById('pinDisplay');
    const passphraseCount = document.getElementById('passphraseCount');
    const isSetup = authForm?.dataset.mode === 'init';
    let lockoutRemaining = parseInt(authForm?.dataset.lockoutSeconds || '0', 10);

    function compactPassphrase(value) {
        return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
    }

    function hasRepeatedShortToken(value) {
        if (value.length < 6) return false;
        const maxTokenLen = Math.min(16, Math.floor(value.length / 2));
        for (let tokenLen = 1; tokenLen <= maxTokenLen; tokenLen += 1) {
            if (value.length % tokenLen !== 0) continue;
            const repeats = value.length / tokenLen;
            const token = value.slice(0, tokenLen);
            if (repeats >= 3 && token.repeat(repeats) === value) return true;
        }
        return false;
    }

    function hasObviousSequence(value) {
        if (value.length < 4) return false;
        for (let i = 0; i <= value.length - 4; i += 1) {
            const chunk = value.slice(i, i + 4);
            if (SEQUENCE_ROWS.some(row => row.includes(chunk) || row.split('').reverse().join('').includes(chunk))) {
                return true;
            }
        }
        return false;
    }

    function usesCommonWeakPhrase(value) {
        if (COMMON_WEAK.has(value)) return true;
        for (const weak of COMMON_WEAK) {
            if (weak.length >= 6 && value.startsWith(weak) && /^\d+$/.test(value.slice(weak.length))) {
                return true;
            }
        }
        return false;
    }

    function estimateEntropy(value) {
        let poolSize = 0;
        if (/[a-z]/.test(value)) poolSize += 26;
        if (/[A-Z]/.test(value)) poolSize += 26;
        if (/[0-9]/.test(value)) poolSize += 10;
        if (/\s/.test(value)) poolSize += 1;
        if (/[^A-Za-z0-9\s]/.test(value)) poolSize += 33;
        if (poolSize <= 1) return 0;
        return value.length * Math.log2(poolSize);
    }

    function checkPinStrength(value) {
        if (!value) {
            return {
                score: 0,
                label: '---',
                class: '',
                reqs: { length: false, entropy: false, patterns: false, maximum: true }
            };
        }

        const compact = compactPassphrase(value);
        const uniqueCount = new Set(value).size;
        const entropy = estimateEntropy(value);
        const patternsOk = uniqueCount >= MIN_UNIQUE
            && !(value === value[0]?.repeat(value.length))
            && !(value.length < NUMERIC_MIN_LENGTH && /^\d+$/.test(value))
            && !hasRepeatedShortToken(compact)
            && !hasObviousSequence(compact)
            && !usesCommonWeakPhrase(compact);

        const reqs = {
            length: value.length >= MIN_LENGTH,
            entropy: entropy >= MIN_ENTROPY,
            patterns: patternsOk,
            maximum: value.length <= MAX_LENGTH
        };

        let score = 0;
        Object.values(reqs).forEach(valid => {
            if (valid) score += 25;
        });

        let label = window.PARACCI_I18N?.status_weak || 'Weak';
        let statusClass = 'weak';
        if (value.length < MIN_LENGTH) {
            label = window.PARACCI_I18N?.status_short || 'Short';
        } else if (score >= 100) {
            label = window.PARACCI_I18N?.status_strong || 'Strong';
            statusClass = 'strong';
        } else if (score >= 75) {
            label = window.PARACCI_I18N?.status_medium || 'Medium';
            statusClass = 'medium';
        }

        return { score, label, class: statusClass, reqs };
    }

    function updatePinDisplay() {
        if (!pinInput) return;
        const value = pinInput.value;
        const cappedLength = Math.min(value.length, MAX_LENGTH);
        const thresholds = [1, 6, 12, 24, 64, 128];
        const filledDots = value.length === 0 ? 0 : thresholds.filter(threshold => cappedLength >= threshold).length || 1;

        pinDots.forEach((dot, index) => {
            const span = dot.querySelector('span');
            dot.classList.remove('filled', 'revealed');
            if (index < filledDots) dot.classList.add('filled');
            if (pinInput.type === 'text') dot.classList.add('revealed');
            if (span) {
                if (pinInput.type === 'text' && pinInput.maxLength > 0 && pinInput.maxLength <= 8 && index < value.length) {
                    span.textContent = value[index];
                } else {
                    span.textContent = '';
                }
            }
        });

        if (pinDisplay) {
            pinDisplay.setAttribute('aria-label', `${cappedLength} characters entered`);
        }
        if (passphraseCount) {
            passphraseCount.textContent = `${cappedLength} / ${MAX_LENGTH}`;
            passphraseCount.classList.toggle('over-limit', value.length > MAX_LENGTH);
        }

        const strengthFill = document.getElementById('strengthFill');
        const strengthStatus = document.getElementById('strengthStatus');
        const strengthChecklist = document.getElementById('strengthChecklist');

        if (strengthFill && strengthStatus) {
            const result = checkPinStrength(value);
            strengthFill.className = 'progress-fill';
            strengthStatus.className = 'strength-status';

            if (value.length > 0) {
                strengthFill.classList.add('strength-' + result.class);
                strengthStatus.classList.add('status-' + result.class);
                strengthStatus.textContent = result.label;
            } else {
                strengthStatus.textContent = '---';
            }

            if (strengthChecklist) {
                Object.keys(result.reqs).forEach(reqKey => {
                    const li = strengthChecklist.querySelector(`[data-req="${reqKey}"]`);
                    if (li) li.classList.toggle('valid', result.reqs[reqKey]);
                });
            }
        }
    }

    function updateLockoutCountdown() {
        const countdown = document.getElementById('lockoutCountdown');
        const alert = document.getElementById('lockoutAlert');
        if (countdown) countdown.textContent = String(Math.max(0, lockoutRemaining));
        if (lockoutRemaining <= 0) {
            if (submitBtn) submitBtn.disabled = false;
            if (alert) alert.style.display = 'none';
            return;
        }
        if (submitBtn) submitBtn.disabled = true;
        lockoutRemaining -= 1;
        window.setTimeout(updateLockoutCountdown, 1000);
    }

    if (pinDisplay && pinInput) {
        pinDisplay.addEventListener('click', () => pinInput.focus());
    }

    const pinToggle = document.getElementById('pinToggle');
    if (pinToggle && pinInput) {
        pinToggle.addEventListener('click', () => {
            pinInput.type = pinInput.type === 'password' ? 'text' : 'password';
            const isRevealed = pinInput.type === 'text';
            pinInput.classList.toggle('revealed-input', isRevealed);
            pinToggle.classList.toggle('active', isRevealed);
            if (pinDisplay) {
                pinDisplay.style.display = isRevealed ? 'none' : 'flex';
            }
            updatePinDisplay();
        });
    }

    if (pinInput) {
        pinInput.addEventListener('input', updatePinDisplay);
        pinInput.focus();
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'A' && e.target.tagName !== 'INPUT') {
                pinInput.focus();
            }
        });
        if (pinToggle) {
            const isRevealed = pinInput.type === 'text';
            pinInput.classList.toggle('revealed-input', isRevealed);
            pinToggle.classList.toggle('active', isRevealed);
            if (pinDisplay) {
                pinDisplay.style.display = isRevealed ? 'none' : 'flex';
            }
        }
        updatePinDisplay();
    }

    if (authForm && submitBtn) {
        authForm.addEventListener('submit', (e) => {
            if (!pinInput) return;
            if (lockoutRemaining > 0) {
                e.preventDefault();
                return;
            }
            if (isSetup && (pinInput.value.length < MIN_LENGTH || pinInput.value.length > MAX_LENGTH)) {
                e.preventDefault();
                const strengthStatus = document.getElementById('strengthStatus');
                if (strengthStatus) {
                    strengthStatus.textContent = window.PARACCI_I18N?.status_short || 'Short';
                    strengthStatus.classList.add('status-weak');
                }
                return;
            }
            if (!isSetup && pinInput.value.length > MAX_LENGTH) {
                e.preventDefault();
                return;
            }
            const armorText = authForm.dataset.armorText || window.PARACCI_I18N?.quantum_armor || 'Quantum Armor Active...';
            const spinner = document.createElement('span');
            spinner.className = 'spinner';
            submitBtn.disabled = true;
            submitBtn.classList.add('btn-loading');
            submitBtn.replaceChildren(spinner, document.createTextNode(` ${armorText}`));
        });
    }

    if (lockoutRemaining > 0) {
        updateLockoutCountdown();
    }
});
