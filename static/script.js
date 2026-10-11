/* ═══════════════════════════════════════════════
   PhishGuard - Neural Threat Console
   Script v2.1 - Particle system + Timer ring + Game logic
   ═══════════════════════════════════════════════ */

// ─── Game State ─────────────────────────────────
const state = {
  currentEmail: null,
  score: 0,
  attempts: 0,
  timeLeft: 10,
  timerId: null,
  busy: false,
  answered: false,
  retryCount: 0,
  maxRetry: 2,
  paused: false,
  consecutiveTimeouts: 0,  // resets when user answers; increments on timeout
  autoPaused: false,       // true after 3 consecutive timeouts
};

const elements = {};

// ─── Particle Canvas System ─────────────────────
const ParticleSystem = (() => {
  let canvas, ctx;
  let particles = [];
  let animFrameId = null;
  let mouse = { x: -1000, y: -1000 };
  const CONNECTION_DIST = 140;
  const MOUSE_RADIUS = 180;

  // PERF-02: Cache particle color per-frame instead of per-particle/draw call
  let _cachedColor = '0, 240, 255';

  function refreshParticleColor() {
    const raw = getComputedStyle(document.documentElement).getPropertyValue('--particle-color').trim();
    _cachedColor = raw || '0, 240, 255';
  }

  function getParticleColor() {
    return _cachedColor;
  }

  function getParticleCount() {
    if (window.innerWidth < 768) return 40;
    if (window.innerWidth < 1200) return 70;
    return 100;
  }

  class Particle {
    constructor() {
      this.reset();
    }

    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - 0.5) * 0.4;
      this.vy = (Math.random() - 0.5) * 0.4;
      this.radius = Math.random() * 2.0 + 0.8;
      this.opacity = Math.random() * 0.6 + 0.25;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      // Mouse repulsion
      const dx = this.x - mouse.x;
      const dy = this.y - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < MOUSE_RADIUS && dist > 0) {
        const force = (MOUSE_RADIUS - dist) / MOUSE_RADIUS * 0.02;
        this.vx += (dx / dist) * force;
        this.vy += (dy / dist) * force;
      }

      // Damping
      this.vx *= 0.999;
      this.vy *= 0.999;

      // Wrap edges
      if (this.x < 0) this.x = canvas.width;
      if (this.x > canvas.width) this.x = 0;
      if (this.y < 0) this.y = canvas.height;
      if (this.y > canvas.height) this.y = 0;
    }

    draw() {
      const color = getParticleColor();
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${color}, ${this.opacity})`;
      ctx.fill();
    }
  }

  function drawConnections() {
    const color = getParticleColor();
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECTION_DIST) {
          const opacity = (1 - dist / CONNECTION_DIST) * 0.35;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(${color}, ${opacity})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }
  }

  function animate() {
    // PERF-02: Refresh the cached color once per frame
    refreshParticleColor();

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach((p) => {
      p.update();
      p.draw();
    });
    drawConnections();
    animFrameId = requestAnimationFrame(animate);
  }

  function handleResize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const target = getParticleCount();
    while (particles.length < target) particles.push(new Particle());
    while (particles.length > target) particles.pop();
  }

  function init(canvasEl) {
    canvas = canvasEl;
    ctx = canvas.getContext('2d');
    handleResize();

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', (e) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    });
    window.addEventListener('touchmove', (e) => {
      if (e.touches.length > 0) {
        mouse.x = e.touches[0].clientX;
        mouse.y = e.touches[0].clientY;
      }
    }, { passive: true });
    window.addEventListener('mouseleave', () => {
      mouse.x = -1000;
      mouse.y = -1000;
    });

    animate();
  }

  return { init };
})();

// ─── Theme Manager ──────────────────────────────
const ThemeManager = (() => {
  const STORAGE_KEY = 'phishguard-theme';

  function getPreferred() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
    // Respect OS preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      return 'light';
    }
    return 'dark';
  }

  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
  }

  function toggle() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    apply(current === 'dark' ? 'light' : 'dark');
  }

  function init() {
    // Apply saved/preferred theme immediately
    apply(getPreferred());

    const btn = document.getElementById('theme-toggle');
    if (btn) {
      btn.addEventListener('click', toggle);
    }

    // Listen for OS theme changes
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
        if (!localStorage.getItem(STORAGE_KEY)) {
          apply(e.matches ? 'light' : 'dark');
        }
      });
    }
  }

  return { init, toggle };
})();

// ─── Timer Ring ─────────────────────────────────
const TIMER_CIRCUMFERENCE = 2 * Math.PI * 28; // r=28 from SVG

function updateTimerRing(timeLeft) {
  const ring = elements.timerRing;
  if (!ring) return;

  const fraction = timeLeft / 10;
  const offset = TIMER_CIRCUMFERENCE * (1 - fraction);
  ring.style.strokeDashoffset = offset;

  // Color shift based on time remaining
  ring.classList.remove('warning', 'critical');
  if (timeLeft <= 3) {
    ring.classList.add('critical');
  } else if (timeLeft <= 5) {
    ring.classList.add('warning');
  }
}

function resetTimerRing() {
  const ring = elements.timerRing;
  if (!ring) return;
  ring.style.strokeDashoffset = '0';
  ring.classList.remove('warning', 'critical');
}

// ─── Stats Update ───────────────────────────────
function updateStats() {
  elements.scoreValue.textContent = state.score.toString();
  elements.attemptsValue.textContent = state.attempts.toString();
}

// ─── Status Messages ────────────────────────────
function setStatus(message, tone = 'neutral') {
  elements.status.style.opacity = '0';
  elements.status.style.transform = 'translateY(4px)';

  setTimeout(() => {
    elements.status.textContent = message;
    elements.status.dataset.tone = tone;
    elements.status.style.opacity = '1';
    elements.status.style.transform = 'translateY(0)';
  }, 150);
}

// ─── Timer ──────────────────────────────────────
function updateTimer() {
  elements.timerValue.textContent = `${state.timeLeft}s`;
  updateTimerRing(state.timeLeft);
}

function startTimer() {
  clearInterval(state.timerId);
  state.timeLeft = 10;
  resetTimerRing();
  updateTimer();
  state.paused = false;
  elements.pauseButton.textContent = 'Pause Timer';
  state.timerId = setInterval(() => {
    if (state.paused) {
      return;
    }
    state.timeLeft -= 1;
    updateTimer();
    if (state.timeLeft <= 0) {
      clearInterval(state.timerId);
      handleTimeout();
    }
  }, 1000);
}

function handleTimeout() {
  if (state.answered || !state.currentEmail) {
    return;
  }
  state.answered = true;
  state.attempts += 1;
  updateStats();
  const label = state.currentEmail.label === 'legitimate' ? 'legitimate' : 'phishing';
  setStatus(`Time's up. That one was ${label}.`, 'warning');
  triggerEmailEffect('shake');

  state.consecutiveTimeouts += 1;

  if (state.consecutiveTimeouts >= 3) {
    // Auto-pause: user has missed 3 in a row - give them a break
    state.autoPaused = true;
    elements.pauseButton.textContent = 'Resume Game';
    setTimeout(() => {
      setStatus(
        `You've timed out ${state.consecutiveTimeouts} times in a row. Take a breather - press "Resume Game" when ready.`,
        'warning'
      );
    }, 1800);
  } else {
    setTimeout(loadEmail, 1800);
  }
}

// ─── Email Card Visual Effects ──────────────────
function triggerEmailEffect(effectClass) {
  const card = elements.emailBox;
  if (!card) return;
  card.classList.remove('shake', 'correct-pulse');
  // Force reflow for re-triggering animation
  void card.offsetWidth;
  card.classList.add(effectClass);
  setTimeout(() => card.classList.remove(effectClass), 700);
}

// ─── Consensus Badge ─────────────────────────────
function showVerifiedBadge(consensusRound, qualityScore) {
  removeVerifiedBadge();
  const badge = document.createElement('div');
  badge.id = 'consensus-badge';
  badge.className = 'consensus-badge';

  let qualityLabel = 'Dual-AI Verified';
  let qualityIcon = '✓';

  if (qualityScore >= 5) {
    qualityLabel = 'Elite Scenario';
    qualityIcon = '🔥';
    badge.classList.add('quality-elite');
  } else if (qualityScore >= 4) {
    qualityLabel = 'Creative';
    qualityIcon = '✨';
    badge.classList.add('quality-creative');
  }

  badge.setAttribute('aria-label', `${qualityLabel} - verified in ${consensusRound} round${consensusRound !== 1 ? 's' : ''}`);
  badge.innerHTML =
    `<span class="consensus-badge__icon" aria-hidden="true">${qualityIcon}</span>` +
    `<span class="consensus-badge__text">${qualityLabel}</span>` +
    `<span class="consensus-badge__round">Round ${consensusRound}</span>`;
  elements.emailBox.appendChild(badge);
}

function removeVerifiedBadge() {
  const existing = document.getElementById('consensus-badge');
  if (existing) existing.remove();
}

// ─── Load Email ─────────────────────────────────
function loadEmail() {
  if (state.busy) {
    return;
  }
  state.busy = true;
  removeVerifiedBadge();
  setStatus('AI models reaching consensus\u2026', 'neutral');
  const endpoint = '/get-email';

  fetch(endpoint, {
    headers: {
      // SEC-01: Custom header for CSRF protection (cannot be set by cross-origin form submissions)
      'X-Requested-With': 'XMLHttpRequest',
    },
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      if (!data.text || !data.label) {
        throw new Error('Invalid email payload.');
      }
      state.retryCount = 0;
      state.currentEmail = data;
      state.answered = false;
      elements.emailContent.textContent = data.text;

      // Show validated badge if consensus was reached
      if (data._validated && data._consensus_round > 0) {
        showVerifiedBadge(data._consensus_round, data._quality_score || 0);
      }

      setStatus('Make your call: phishing or legitimate?', 'neutral');
      startTimer();
    })
    .catch((error) => {
      console.error('Error fetching email:', error);
      elements.emailContent.textContent = 'We could not load a message right now. Please try again shortly.';
      if (state.retryCount < state.maxRetry) {
        state.retryCount += 1;
        setStatus('Temporary service issue. Retrying now...', 'warning');
        setTimeout(loadEmail, 2000);
      } else {
        setStatus('Connection issue. Please refresh or try again in a moment.', 'error');
      }
    })
    .finally(() => {
      state.busy = false;
    });
}

// ─── Handle Answer ──────────────────────────────
function handleAnswer(choice) {
  if (state.answered || !state.currentEmail) {
    return;
  }
  state.answered = true;
  clearInterval(state.timerId);
  state.paused = false;
  state.consecutiveTimeouts = 0;  // user engaged - reset the streak
  elements.pauseButton.textContent = 'Pause Timer';
  const isCorrect = choice === state.currentEmail.label;
  state.attempts += 1;
  if (isCorrect) {
    state.score += 1;
  }
  updateStats();

  if (isCorrect) {
    setStatus('Correct! You spotted it.', 'success');
    triggerEmailEffect('correct-pulse');
  } else {
    const label = state.currentEmail.label === 'legitimate' ? 'legitimate' : 'phishing';
    setStatus(`Close call. That message was ${label}.`, 'warning');
    triggerEmailEffect('shake');
  }
  setTimeout(loadEmail, 1800);
}

// ─── Pause Toggle ───────────────────────────────
function togglePause() {
  // If the game was auto-paused due to consecutive timeouts, treat this as a full resume
  if (state.autoPaused) {
    state.autoPaused = false;
    state.consecutiveTimeouts = 0;
    elements.pauseButton.textContent = 'Pause Timer';
    setStatus('Back in action! Make your call.', 'neutral');
    loadEmail();
    return;
  }

  if (!state.currentEmail || state.answered) {
    return;
  }
  state.paused = !state.paused;
  elements.pauseButton.textContent = state.paused ? 'Resume Timer' : 'Pause Timer';
  if (state.paused) {
    setStatus('Timer paused. Make your call when ready.', 'neutral');
  } else {
    setStatus('Timer resumed. Make your call.', 'neutral');
  }
}

// ─── Feedback ───────────────────────────────────
function submitFeedback(event) {
  event.preventDefault();
  const feedbackText = elements.feedbackInput.value.trim();
  if (!feedbackText) {
    setStatus('Add a quick note before sending feedback.', 'warning');
    return;
  }

  elements.feedbackButton.disabled = true;
  setStatus('Sending your feedback...', 'neutral');

  fetch('/submit-feedback', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // SEC-01: Custom header for CSRF protection
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify({ feedback: feedbackText }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      elements.feedbackInput.value = '';
      elements.feedbackCounter.textContent = '0 / 300';
      setStatus(data.message || 'Feedback received. Thank you!', 'success');
    })
    .catch((error) => {
      console.error('Error submitting feedback:', error);
      setStatus('Feedback failed to send. Please try again.', 'error');
    })
    .finally(() => {
      elements.feedbackButton.disabled = false;
    });
}

function updateCounter() {
  const count = elements.feedbackInput.value.length;
  elements.feedbackCounter.textContent = `${count} / 300`;
}

// ─── Status transition styling ──────────────────
function initStatusTransitions() {
  const status = elements.status;
  if (!status) return;
  status.style.transition = 'opacity 0.3s ease, transform 0.3s ease, background 0.4s ease, color 0.4s ease, border-color 0.4s ease';
}

// ─── Initialize ─────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Cache DOM elements
  elements.emailContent = document.getElementById('email-content');
  elements.emailBox = document.getElementById('email-box');
  elements.timerValue = document.getElementById('timer-value');
  elements.timerRing = document.getElementById('timer-ring');
  elements.scoreValue = document.getElementById('score-value');
  elements.attemptsValue = document.getElementById('attempts-value');
  elements.status = document.getElementById('status');
  elements.phishingButton = document.getElementById('phishing-button');
  elements.legitButton = document.getElementById('legit-button');
  elements.pauseButton = document.getElementById('pause-button');
  elements.feedbackForm = document.getElementById('feedback-form');
  elements.feedbackInput = document.getElementById('feedback-text');
  elements.feedbackButton = document.getElementById('feedback-submit');
  elements.feedbackCounter = document.getElementById('feedback-counter');

  // Event listeners
  elements.phishingButton.addEventListener('click', () => handleAnswer('phishing'));
  elements.legitButton.addEventListener('click', () => handleAnswer('legitimate'));
  elements.pauseButton.addEventListener('click', togglePause);
  elements.feedbackForm.addEventListener('submit', submitFeedback);
  elements.feedbackInput.addEventListener('input', updateCounter);

  // Initialize systems
  ThemeManager.init();
  initStatusTransitions();
  updateStats();
  updateCounter();

  // Particle canvas
  const canvas = document.getElementById('particle-canvas');
  if (canvas) {
    ParticleSystem.init(canvas);
  }

  // Start the game
  loadEmail();
});
