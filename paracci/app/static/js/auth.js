/**
 * Paracci Auth / Unlock Logic
 */

document.addEventListener('DOMContentLoaded', () => {
    const authForm = document.getElementById('authForm');
    const submitBtn = document.getElementById('submitBtn');
    const pinInput = document.getElementById('pinInput');
    const pinDots = document.querySelectorAll('.pin-dot');

    // Focus hidden input on click anywhere in display
    const pinDisplay = document.getElementById('pinDisplay');
    if (pinDisplay) {
        pinDisplay.addEventListener('click', () => pinInput.focus());
    }

    // PIN Visibility Toggle
    const pinToggle = document.getElementById('pinToggle');
    let isPinVisible = !pinToggle; // Default to visible if toggle is not present (like in 2FA verify)

    if (pinToggle) {
        pinToggle.addEventListener('click', () => {
            isPinVisible = !isPinVisible;
            pinToggle.classList.toggle('active', isPinVisible);
            updatePinDisplay();
        });
    }

    function checkPinStrength(pin) {
        if (!pin) return { score: 0, label: '—', class: '', reqs: { length: false, sequence: true, unique: false } };
        
        const reqs = {
            length: pin.length >= 8,
            sequence: true,
            unique: new Set(pin).size >= 3
        };

        // Sequential check (e.g. 1234)
        const sequential = "01234567890 98765432109";
        for (let i = 0; i <= pin.length - 4; i++) {
            if (sequential.includes(pin.substr(i, 4))) {
                reqs.sequence = false;
                break;
            }
        }

        let score = 0;
        if (reqs.length) score += 40;
        if (reqs.sequence) score += 30;
        if (reqs.unique) score += 30;

        let label = window.PARACCI_I18N?.status_weak || 'Weak';
        let statusClass = 'weak';

        if (pin.length < 8) {
            label = window.PARACCI_I18N?.status_short || 'Short';
        } else if (score >= 100) {
            label = window.PARACCI_I18N?.status_strong || 'Strong';
            statusClass = 'strong';
        } else if (score >= 60) {
            label = window.PARACCI_I18N?.status_medium || 'Medium';
            statusClass = 'medium';
        }

        return { score, label, class: statusClass, reqs };
    }

    function updatePinDisplay() {
        const val = pinInput.value;
        
        // Update dots
        pinDots.forEach((dot, index) => {
            const span = dot.querySelector('span');
            
            // Base classes reset
            dot.classList.remove('filled', 'revealed');
            
            if (isPinVisible) {
                // In revealed mode, all dots show as boxes
                dot.classList.add('revealed');
                if (span) span.textContent = index < val.length ? val[index] : '';
            } else {
                // In hidden mode, dots only show as filled if they have a value
                if (index < val.length) {
                    dot.classList.add('filled');
                }
                if (span) span.textContent = '';
            }
        });

        // Update Strength (if element exists)
        const strengthFill = document.getElementById('strengthFill');
        const strengthStatus = document.getElementById('strengthStatus');
        const strengthChecklist = document.getElementById('strengthChecklist');

        if (strengthFill && strengthStatus) {
            const result = checkPinStrength(val);
            
            // Update bar and label
            strengthFill.className = 'progress-fill';
            strengthStatus.className = 'strength-status';
            
            if (val.length > 0) {
                strengthFill.classList.add('strength-' + result.class);
                strengthStatus.classList.add('status-' + result.class);
                strengthStatus.textContent = result.label;
            } else {
                strengthStatus.textContent = '—';
            }

            // Update Checklist
            if (strengthChecklist) {
                Object.keys(result.reqs).forEach(reqKey => {
                    const li = strengthChecklist.querySelector(`[data-req="${reqKey}"]`);
                    if (li) {
                        li.classList.toggle('valid', result.reqs[reqKey]);
                    }
                });
            }
        }
    }

    if (pinInput) {
        pinInput.addEventListener('input', () => {
            updatePinDisplay();
        });
        
        // Auto-focus logic
        pinInput.focus();
        document.addEventListener('keydown', (e) => {
            if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'A' && e.target.tagName !== 'INPUT') {
                pinInput.focus();
            }
        });
    }

    if (authForm && submitBtn) {
        authForm.addEventListener('submit', (e) => {
            if (pinInput && pinInput.value.length < 8) {
                e.preventDefault();
                const strengthStatus = document.getElementById('strengthStatus');
                if (strengthStatus) {
                    strengthStatus.textContent = window.PARACCI_I18N?.status_short || 'Short';
                    strengthStatus.classList.add('status-weak');
                }
                return;
            }
            const armorText = authForm.dataset.armorText || window.PARACCI_I18N?.quantum_armor || 'Quantum Armor Active...';
            submitBtn.disabled = true;
            submitBtn.classList.add('btn-loading');
            submitBtn.innerHTML = `<span class="spinner"></span> ${armorText}`;
        });
    }
});
