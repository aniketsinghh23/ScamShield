const threatIndex = document.getElementById('threatIndex');
const threat24Hours = document.getElementById('threat24Hours');
const threatRansomware = document.getElementById('threatRansomware');
const threatRecords = document.getElementById('threatRecords');
const threatsMeta = document.getElementById('threatsMeta');
const threatsError = document.getElementById('threatsError');
const recentBreaches = document.getElementById('recentBreaches');
const recentLeaks = document.getElementById('recentLeaks');

const chartColors = {
    text: '#1E3B2F',
    muted: '#40594A',
    primary: '#7F8C6A',
    accent: '#C8B48A'
};

function renderChart(canvasId, type, labels, values, label, color) {
    const canvas = document.getElementById(canvasId);
    if (!window.Chart || !canvas) {
        return;
    }

    new Chart(canvas, {
        type,
        data: {
            labels,
            datasets: [{
                label,
                data: values,
                backgroundColor: color,
                borderColor: color,
                borderWidth: 1,
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    ticks: { color: chartColors.muted },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: chartColors.muted, precision: 0 },
                    grid: { color: 'rgba(30, 59, 47, 0.1)' }
                }
            }
        }
    });
}

function appendRows(target, rows, columns, emptyMessage) {
    target.replaceChildren();

    if (!rows.length) {
        const row = document.createElement('tr');
        row.innerHTML = `<td class="empty-state" colspan="${columns.length}">${emptyMessage}</td>`;
        target.append(row);
        return;
    }

    rows.forEach(item => {
        const row = document.createElement('tr');
        columns.forEach(column => {
            const cell = document.createElement('td');
            const value = typeof column === 'function' ? column(item) : item[column];
            cell.textContent = value || '—';
            row.append(cell);
        });
        target.append(row);
    });
}

function formatNumber(value) {
    return typeof value === 'number' ? value.toLocaleString() : '—';
}

fetch('/api/realtime')
    .then(async response => {
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Realtime data unavailable.');
        }
        return data;
    })
    .then(data => {
        const index = data.index || {};
        const geo = data.geo || {};
        const series = data.series?.items || [];
        const actors = Array.isArray(data.actors) ? data.actors : [];
        const breaches = Array.isArray(data.breaches) ? data.breaches : [];
        const leaks = Array.isArray(data.leaks?.leaks) ? data.leaks.leaks : [];

        threatIndex.textContent = formatNumber(index.index_today);
        threat24Hours.textContent = formatNumber(index.count_24h);
        threatRansomware.textContent = formatNumber(index.ransomware_7d);
        threatRecords.textContent = index.records_leaked_7d || '—';
        threatsMeta.textContent =
            `${data.source} · Updated ${new Date(index.updated || data.fetched_at).toLocaleString()}`;

        if (data.stale) {
            threatsError.hidden = false;
            threatsError.textContent = 'Some realtime sources could not be refreshed.';
        }

        renderChart(
            'seriesChart',
            'line',
            series.map(item => item.date),
            series.map(item => item.count),
            'Incidents',
            chartColors.primary
        );
        renderChart(
            'geoChart',
            'bar',
            (geo.targets || []).slice(0, 10).map(item => item.country),
            (geo.targets || []).slice(0, 10).map(item => item.count),
            'Targets',
            chartColors.accent
        );
        renderChart(
            'actorChart',
            'bar',
            actors.map(item => item.name),
            actors.map(item => item.count),
            'Activity',
            chartColors.primary
        );

        appendRows(
            recentBreaches,
            breaches,
            [
                item => item.title,
                item => item.severity,
                item => item.country,
                item => item.date
            ],
            'No recent incidents returned by the API.'
        );
        appendRows(
            recentLeaks,
            leaks,
            [
                item => item.group,
                item => item.victim,
                item => item.sector,
                item => item.status
            ],
            'No leak listings returned by the API.'
        );
    })
    .catch(error => {
        threatsError.hidden = false;
        threatsError.textContent = error.message;
        threatsMeta.textContent = 'No realtime data is available.';
        appendRows(recentBreaches, [], [''], 'Feed unavailable.');
        appendRows(recentLeaks, [], [''], 'Feed unavailable.');
    });
