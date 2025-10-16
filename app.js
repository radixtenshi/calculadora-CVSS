// Copyright FIRST, Red Hat, and contributors
// SPDX-License-Identifier: BSD-2-Clause

const BASE_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
const SUPPLEMENTAL_METRICS = ["S", "AU", "R", "V", "RE", "U"]
const ENV_MODIFIED_METRICS = ["MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
const ENV_SECURITY_METRICS = ["CR", "IR", "AR"]
const THREAT_METRICS = ["E"]

const SCORE_CATEGORIES = [
    { label: "Base Metrics", include: { base: true } },
    { label: "Supplemental Metrics", include: { base: true, supplemental: true } },
    { label: "Environmental (Modified Base Metrics)", include: { base: true, envSecurity: true, envModified: true } },
    { label: "Environmental (Security Requirements)", include: { base: true, envSecurity: true } },
    { label: "Threat Metrics", include: { base: true, threat: true } }
]

const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: cvssConfig,
            maxComposedData: maxComposed,
            maxSeverityData: maxSeverity,
            expectedMetricOrder: expectedMetricOrder,
            cvssMacroVectorDetailsData: cvssMacroVectorDetails,
            cvssMacroVectorValuesData: cvssMacroVectorValues,
            showDetails: false,
            cvssSelected: null,
            defaultSelections: null,
            header_height: 0,
            lookup: cvssLookup_global,
            macroVector: null,
            chartInstance: null
        }
    },
    methods: {
        buttonClass(isPrimary, big = false) {
            result = "btn btn-m"
            if (isPrimary) {
                result += " btn-primary"
            }
            if (!big) {
                result += " btn-sm"
            }

            return result
        },
        scoreClass(qualScore) {
            if (qualScore == "Low") {
                return "c-hand text-success"
            }
            else if (qualScore == "Medium") {
                return "c-hand text-warning"
            }
            else if (qualScore == "High") {
                return "c-hand text-error"
            }
            else if (qualScore == "Critical") {
                return "c-hand text-error text-bold"
            }
            else {
                return "c-hand text-gray"
            }
        },
        copyVector() {
            navigator.clipboard.writeText(this.vector)
            window.location.hash = this.vector
        },
        onButton(metric, value) {
            this.cvssSelected[metric] = value
            window.location.hash = this.vector
        },
        setButtonsToVector(vector) {
            this.resetSelected()
            metrics = vector.split("/")
            // Remove hash + CVSS v4.0 prefix
            prefix = metrics[0].slice(1);
            if (prefix != "CVSS:4.0") {
                console.log("Error invalid vector, missing CVSS v4.0 prefix")
                return
            }
            metrics.shift()

            // Ensure compliance first
            toSelect = {}
            oi = 0
            for (index in metrics) {
                [key, value] = metrics[index].split(":")

                expected = Object.entries(this.expectedMetricOrder)[oi++]
                while (true) {
                    // If out of possible metrics ordering, it not a valid value thus
                    // the vector is invalid
                    if (expected == undefined) {
                        console.log("Error invalid vector, too many metric values")
                        return
                    }
                    if (key != expected[0]) {
                        // If not this metric but is mandatory, the vector is invalid
                        // As the only mandatory ones are from the Base group, 11 is the
                        // number of metrics part of it.
                        if (oi <= 11) {
                            console.log("Error invalid vector, missing mandatory metrics")
                            return
                        }
                        // If a non-mandatory, retry
                        expected = Object.entries(this.expectedMetricOrder)[oi++]
                        continue
                    }
                    break
                }
                // The value MUST be part of the metric's values, case insensitive
                if (!expected[1].includes(value)) {
                    console.log("Error invalid vector, for key " + key + ", value " + value + " is not in " + expected[1])
                    return
                }
                if (key in this.cvssSelected) {
                    toSelect[key] = value
                }
            }

            // Apply iff is compliant
            for (key in toSelect) {
                this.cvssSelected[key] = toSelect[key]
            }
            this.macroVector = macroVector(this.cvssSelected)

        },
        onReset() {
            window.location.hash = ""
        },
        resetSelected() {
            this.cvssSelected = {}
            for ([metricType, metricTypeData] of Object.entries(this.cvssConfigData)) {
                for ([metricGroup, metricGroupData] of Object.entries(metricTypeData.metric_groups)) {
                    for ([metric, metricData] of Object.entries(metricGroupData)) {
                        this.cvssSelected[metricData.short] = metricData.selected
                    }
                }
            }
            this.defaultSelections = JSON.parse(JSON.stringify(this.cvssSelected))
        },
        splitObjectEntries(object, chunkSize) {
            arr = Object.entries(object)
            res = [];
            for (let i = 0; i < arr.length; i += chunkSize) {
                chunk = arr.slice(i, i + chunkSize)
                res.push(chunk)
            }
            return res
        },
        cloneDefaultSelection() {
            if (!this.defaultSelections) {
                return {}
            }
            return JSON.parse(JSON.stringify(this.defaultSelections))
        },
        applyMetricValues(selection, metrics) {
            metrics.forEach((metric) => {
                if (Object.prototype.hasOwnProperty.call(this.cvssSelected, metric)) {
                    selection[metric] = this.cvssSelected[metric]
                }
            })
        },
        calculateCategoryScore(categoryConfig) {
            let selection = this.cloneDefaultSelection()

            if (categoryConfig.include.base || categoryConfig.include.supplemental || categoryConfig.include.envModified || categoryConfig.include.envSecurity || categoryConfig.include.threat) {
                this.applyMetricValues(selection, BASE_METRICS)
            }

            if (categoryConfig.include.supplemental) {
                this.applyMetricValues(selection, SUPPLEMENTAL_METRICS)
            }

            if (categoryConfig.include.envSecurity) {
                this.applyMetricValues(selection, ENV_SECURITY_METRICS)
            }

            if (categoryConfig.include.envModified) {
                this.applyMetricValues(selection, ENV_MODIFIED_METRICS)
            }

            if (categoryConfig.include.threat) {
                this.applyMetricValues(selection, THREAT_METRICS)
            }

            const categoryMacro = macroVector(selection)
            const categoryScore = cvss_score(
                selection,
                this.lookup,
                this.maxSeverityData,
                categoryMacro)

            return Number(categoryScore.toFixed(1))
        },
        severityInfo(score) {
            if (score === 0) {
                return { label: "Ninguno", color: "#4CAF50" }
            }
            if (score < 4.0) {
                return { label: "Bajo", color: "#8BC34A" }
            }
            if (score < 7.0) {
                return { label: "Medio", color: "#FFC107" }
            }
            if (score < 9.0) {
                return { label: "Alto", color: "#FF5722" }
            }
            return { label: "Crítico", color: "#D32F2F" }
        },
        buildChartData() {
            const labels = []
            const scores = []
            const colors = []
            const severities = []

            SCORE_CATEGORIES.forEach((category) => {
                const score = this.calculateCategoryScore(category)
                const severity = this.severityInfo(score)
                labels.push(category.label)
                scores.push(score)
                colors.push(severity.color)
                severities.push(severity.label)
            })

            return { labels: labels, scores: scores, colors: colors, severities: severities }
        },
        initializeChart() {
            const canvas = document.getElementById('scoreChart')
            if (!canvas || !window.Chart) {
                return
            }

            const chartData = this.buildChartData()

            this.chartInstance = new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: chartData.labels,
                    datasets: [{
                        label: 'Puntaje',
                        data: chartData.scores,
                        backgroundColor: chartData.colors,
                        maxBarThickness: 48,
                        severityLabels: chartData.severities
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 10,
                            title: {
                                display: true,
                                text: 'Puntaje'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Tipo de métrica'
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const severity = context.dataset.severityLabels?.[context.dataIndex]
                                    return `Puntaje: ${context.parsed.y.toFixed(1)} (${severity})`
                                }
                            }
                        }
                    }
                }
            })
        },
        updateChart() {
            if (!this.chartInstance) {
                this.initializeChart()
                return
            }

            const chartData = this.buildChartData()
            this.chartInstance.data.labels = chartData.labels
            this.chartInstance.data.datasets[0].data = chartData.scores
            this.chartInstance.data.datasets[0].backgroundColor = chartData.colors
            this.chartInstance.data.datasets[0].severityLabels = chartData.severities
            this.chartInstance.update()
        }
    },
    computed: {
        vector() {
            value = "CVSS:4.0"
            for (metric in this.expectedMetricOrder) {
                selected = this.cvssSelected[metric]
                if (selected != "X") {
                    value = value.concat("/" + metric + ":" + selected)
                }
            }
            return value
        },
        score() {
            return cvss_score(
                this.cvssSelected,
                this.lookup,
                this.maxSeverityData,
                this.macroVector)
        },
        qualScore() {
            if (this.score == 0) {
                return "None"
            }
            else if (this.score < 4.0) {
                return "Low"
            }
            else if (this.score < 7.0) {
                return "Medium"
            }
            else if (this.score < 9.0) {
                return "High"
            }
            else {
                return "Critical"
            }
        },
    },
    beforeMount() {
        this.resetSelected()
    },
    mounted() {
        this.setButtonsToVector(window.location.hash)
        window.addEventListener("hashchange", () => {
            this.setButtonsToVector(window.location.hash)
        })

        const resizeObserver = new ResizeObserver(() => {
            this.header_height = document.getElementById('header').clientHeight
        })

        resizeObserver.observe(document.getElementById('header'))
        this.$nextTick(() => {
            this.updateChart()
        })
    },
    watch: {
        cvssSelected: {
            deep: true,
            handler() {
                this.macroVector = macroVector(this.cvssSelected)
                this.updateChart()
            }
        }
    }
})

app.mount("#app")
