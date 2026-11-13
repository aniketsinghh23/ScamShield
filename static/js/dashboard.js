const userName = document.getElementById('dashboardUserName');
const avatar = document.getElementById('dashboardAvatar');
const logoutButton = document.getElementById('logoutButton');
const scanTabs = document.querySelectorAll('[data-scan-type]');
const scanUrlInput = document.getElementById('scanUrlInput');
const scanMessageInput = document.getElementById('scanMessageInput');
const scanSubmit = document.getElementById('scanSubmit');
const scanForm = document.getElementById('scanForm');
const scanHelper = document.getElementById('scanHelper');
const scanner = document.getElementById('scanner');
const scannerWorkspace = document.getElementById('scannerWorkspace');
const dashboardOverview = document.getElementById('dashboardOverview');
const dashboardInfo = document.getElementById('about');
const dashboardFooter = document.getElementById('feedback');
const dashboardMain = document.querySelector('.dashboard-content');
const dashboardTitle = document.getElementById('dashboardTitle');
const dashboardSubtitle = document.getElementById('dashboardSubtitle');
const dashboardLink = document.querySelector('[data-dashboard-nav]');
const urlScannerLink = document.querySelector('[data-open-scanner="url"]');
const messageScannerLink = document.querySelector('[data-open-scanner="message"]');
const feedbackForm = document.getElementById('dashboardFeedbackForm');
const feedbackStatus = document.getElementById('dashboardFeedbackStatus');
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
const scanHistoryBody = document.getElementById('scanHistoryBody');
const scanActivityChart = document.getElementById('scanActivityChart');
const scanDistribution = document.getElementById('scanDistribution');

const scanTotalCount = document.getElementById('scanTotalCount');
const scanSuspiciousCount = document.getElementById('scanSuspiciousCount');
const scanSafeCount = document.getElementById('scanSafeCount');

const formatScanDate = value => new Date(value).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
});

const renderScanHistory = scans => {
    scanHistoryBody.replaceChildren();
    if (!scans.length) {
        const row = document.createElement('tr');
        row.innerHTML = '<td class="empty-state" colspan="4">No scan records yet.</td>';
        scanHistoryBody.append(row);
        return;
    }

    scans.forEach(scan => {
        const row = document.createElement('tr');
        const input = document.createElement('td');
        input.textContent = scan.input.length > 58
            ? `${scan.input.slice(0, 55)}...`
            : scan.input;
        input.title = scan.input;

        const result = document.createElement('td');
        const status = document.createElement('span');
        status.className = `status ${scan.classification.toLowerCase()}`;
        status.textContent = scan.classification;
        result.append(status);

        const score = document.createElement('td');
        score.className = 'risk-score';
        score.textContent = `${scan.risk_score}/100`;

        const date = document.createElement('td');
        date.textContent = formatScanDate(scan.created_at);

        row.append(input, result, score, date);
        scanHistoryBody.append(row);
    });
};

const renderScanActivity = daily => {
    scanActivityChart.replaceChildren();
    const entries = Array.isArray(daily)
        ? daily.map(item => [item.date, item.count])
        : Object.entries(daily);
    if (!entries.length) {
        const empty = document.createElement('p');
        empty.textContent = 'No scan activity yet.';
        scanActivityChart.append(empty);
        return;
    }

    const max = Math.max(...entries.map(([, count]) => count), 1);
    entries.forEach(([date, count]) => {
        const bar = document.createElement('div');
        bar.className = 'bar';
        bar.style.height = `${Math.max((count / max) * 100, 10)}%`;
        bar.title = `${date}: ${count} scan${count === 1 ? '' : 's'}`;
        scanActivityChart.append(bar);
    });
};

const renderScanDistribution = summary => {
    scanDistribution.replaceChildren();
    const total = summary.total || 0;
    if (!total) {
        const empty = document.createElement('p');
        empty.className = 'empty-state';
        empty.textContent = 'No scan distribution is available yet.';
        scanDistribution.append(empty);
        return;
    }

    const donut = document.createElement('div');
    donut.className = 'donut';
    const safeEnd = (summary.safe / total) * 100;
    const suspiciousEnd = safeEnd + (summary.suspicious / total) * 100;
    donut.style.background = `conic-gradient(${[
        `#7F8C6A 0 ${safeEnd}%`,
        `#C8B48A ${safeEnd}% ${suspiciousEnd}%`,
        `#8A3D2B ${suspiciousEnd}% 100%`
    ].join(', ')})`;
    const inner = document.createElement('div');
    inner.className = 'donut-inner';
    inner.innerHTML = `<span>${total}</span><small>Total scans</small>`;
    donut.append(inner);

    const legend = document.createElement('div');
    legend.className = 'legend';
    [['Safe', summary.safe], ['Suspicious', summary.suspicious], ['Dangerous', summary.dangerous]]
        .forEach(([label, count]) => {
            const item = document.createElement('span');
            item.textContent = `${label}: ${count}`;
            legend.append(item);
        });
    scanDistribution.append(donut, legend);
};

const loadScanData = () => fetch('/api/scans?limit=20')
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Unable to load scan history.');
        }
        return data;
    })
    .then(data => fetch('/api/analytics')
        .then(async response => {
            const analytics = await response.json();
            if (!response.ok) {
                throw new Error(analytics.error || 'Unable to load analytics.');
            }
            return { data, analytics };
        }))
    .then(({ data, analytics }) => {
        const { summary } = data;
        scanTotalCount.textContent = summary.total;
        scanSuspiciousCount.textContent = summary.suspicious + summary.dangerous;
        scanSafeCount.textContent = summary.safe;
        renderScanHistory(data.scans);
        renderScanActivity(analytics.charts.daily_scans);
        renderScanDistribution(summary);
    });

const setActiveNav = activeLink => {
    document.querySelectorAll('.side-nav a').forEach(link => {
        link.classList.toggle('active', link === activeLink);
    });
};

const showScanner = mode => {
    scannerWorkspace.hidden = false;
    dashboardOverview.hidden = true;
    dashboardInfo.hidden = true;
    dashboardFooter.hidden = true;
    dashboardMain.classList.add('scanner-mode');
    dashboardTitle.textContent = mode === 'message'
        ? 'Message scanner'
        : 'Scanner tools';
    dashboardSubtitle.textContent = mode === 'message'
        ? 'Review a suspicious message before you respond or share information.'
        : 'Review a suspicious link before you open it.';
    document.querySelector(`[data-scan-type="${mode}"]`)?.click();
    scanner.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

scanTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const isMessageMode = tab.dataset.scanType === 'message';

        scanTabs.forEach(item => {
            const isActive = item === tab;
            item.classList.toggle('active', isActive);
            item.setAttribute('aria-selected', String(isActive));
        });

        scanUrlInput.hidden = isMessageMode;
        scanMessageInput.hidden = !isMessageMode;
        scanSubmit.textContent = isMessageMode ? '⌕ Analyze message' : '⌕ Analyze URL';
        scanHelper.textContent = isMessageMode
            ? 'Enter a message to analyze.'
            : 'Enter a URL to analyze.';

        (isMessageMode ? scanMessageInput : scanUrlInput).focus();
    });
});

scanForm?.addEventListener('submit', event => {
    event.preventDefault();
    const activeTab = document.querySelector('[data-scan-type].active');
    const type = activeTab?.dataset.scanType || 'url';
    const input = type === 'message' ? scanMessageInput.value.trim() : scanUrlInput.value.trim();

    if (!input) {
        scanHelper.textContent = type === 'message'
            ? 'Enter a message to analyze.'
            : 'Enter a URL to analyze.';
        return;
    }

    scanSubmit.disabled = true;
    scanHelper.textContent = 'Analyzing...';
    fetch('/api/scans', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ type, value: input })
    })
        .then(async response => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Unable to analyze this input.');
            }
            return data.scan;
        })
        .then(scan => {
            const modelResult = scan.model_prediction
                ? ` ML model: ${scan.model_prediction} (${Math.round(scan.model_confidence * 100)}%).`
                : '';
            scanHelper.textContent =
                `${scan.classification}: risk score ${scan.risk_score}/100.${modelResult} ${scan.reasons[0]}`;
            scanForm.reset();
            return loadScanData();
        })
        .catch(error => {
            scanHelper.textContent = error.message;
        })
        .finally(() => {
            scanSubmit.disabled = false;
        });
});

urlScannerLink?.addEventListener('click', () => {
    setActiveNav(urlScannerLink);
    showScanner('url');
});

messageScannerLink?.addEventListener('click', () => {
    setActiveNav(messageScannerLink);
    showScanner('message');
});

dashboardLink?.addEventListener('click', () => {
    setActiveNav(dashboardLink);
    scannerWorkspace.hidden = true;
    dashboardOverview.hidden = false;
    dashboardInfo.hidden = false;
    dashboardFooter.hidden = false;
    dashboardMain.classList.remove('scanner-mode');
    dashboardTitle.textContent = 'Your security overview';
    dashboardSubtitle.textContent =
        'Analyze suspicious content and review your recent scan activity.';
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

feedbackForm?.addEventListener('submit', event => {
    event.preventDefault();

    if (!feedbackForm.checkValidity()) {
        feedbackForm.reportValidity();
        return;
    }

    const email = document.getElementById('dashboardFeedbackEmail').value.trim();
    const message = document.getElementById('dashboardFeedbackMessage').value.trim();
    const submitButton = feedbackForm.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    feedbackStatus.textContent = 'Sending your feedback...';

    fetch('/api/feedback', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({ email, message })
    })
        .then(async response => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'Unable to send feedback.');
            }
            return data;
        })
        .then(data => {
            feedbackStatus.textContent = data.message;
            feedbackForm.reset();
        })
        .catch(error => {
            feedbackStatus.textContent = error.message;
        })
        .finally(() => {
            submitButton.disabled = false;
        });
});

fetch('/api/auth/me')
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Your session has expired.');
        }
        return data.user;
    })
    .then(user => {
        userName.textContent = user.name;
        avatar.textContent = user.name.charAt(0).toUpperCase();
    })
    .catch(() => {
        window.location.href = '/login';
    });

loadScanData().catch(() => {
    scanHelper.textContent = 'Unable to load your scan history.';
});

logoutButton?.addEventListener('click', () => {
    logoutButton.disabled = true;
    fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken }
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Unable to log out.');
            }
            window.location.href = '/login';
        })
        .catch(() => {
            logoutButton.disabled = false;
        });
});
