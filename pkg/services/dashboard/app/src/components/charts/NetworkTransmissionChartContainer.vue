<template>
    <div class="column">
        <div class="text-h6">Node: {{ nodeID }}</div>
        <div class="network-tx-chart">
            <network-transmission-chart id="network-tx-chart" v-if="loaded" :options="chartOptions" :data="chartData" />
            <q-inner-loading :showing="!loaded">
                <q-spinner-grid size="xl" color="primary" />
            </q-inner-loading>
        </div>
    </div>
</template>

<script lang="ts">
import { defineComponent, ref, shallowRef } from 'vue';

import { GetStatusRequest, Status } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_pb';
import { useClientStore } from 'stores/client-store';
import NetworkTransmissionChart, { ChartData } from './NetworkTransmissionChart.vue';

const chartOptions: object = { 
    responsive: true, 
    maintainAspectRatio: false,
}

export default defineComponent({
    name: 'NetworkTransmissionChartContainer',
    components: { NetworkTransmissionChart },
    unmounted() {
        clearInterval(this.interval);
    },
    mounted() {
        const clients = useClientStore();

        let lastTX = 0;
        let lastRX = 0;
        const maxDataPoints = 20;
        const txObservations: number[] = [];
        const rxObservations: number[] = [];
        const txDatasets: number[] = [];
        const rxDatasets: number[] = [];
        const labels: string[] = [];

        const interval = setInterval(() => {
            clients.nodeClient.getStatus(new GetStatusRequest(), {}, (err: Error, status: Status) => {
                if (err) {
                    console.error(err);
                    return;
                }
                this.nodeID = status.getId();
                const metrics = status.getInterfaceMetrics();
                if (!metrics) return;
                if (lastTX === 0) {
                    lastTX = metrics.getTotalTransmitBytes();
                    lastRX = metrics.getTotalReceiveBytes();
                }
                if (labels.length >= maxDataPoints) {
                    labels.shift();
                    txDatasets.shift();
                    rxDatasets.shift();
                    txObservations.shift();
                    rxObservations.shift();
                }
                const now = new Date();
                labels.push(now.toUTCString());
                txObservations.push(metrics.getTotalTransmitBytes() - lastTX);
                rxObservations.push(metrics.getTotalReceiveBytes() - lastRX);
                lastTX = metrics.getTotalTransmitBytes();
                lastRX = metrics.getTotalReceiveBytes();
                const totalTX = txObservations.reduce((a, b) => a + b, 0);
                const totalRX = rxObservations.reduce((a, b) => a + b, 0);
                const txPerSec = totalTX / txObservations.length;
                const rxPerSec = totalRX / rxObservations.length;
                txDatasets.push(txPerSec);
                rxDatasets.push(rxPerSec);
                this.loaded = true;
                this.chartData = { 
                    labels: labels,
                    datasets: [
                        {
                            label: 'TX Bytes/Sec',
                            data: txDatasets,
                            borderColor: '#00b0ff',
                            backgroundColor: '#00b0ff',
                            fill: true,
                            cubicInterpolationMode: 'monotone',
                            tension: 0.4
                        },
                        {
                            label: 'RX Bytes/Sec',
                            data: rxDatasets,
                            borderColor: '#ff4081',
                            backgroundColor: '#ff4081',
                            fill: true,
                            cubicInterpolationMode: 'monotone',
                            tension: 0.4
                        }
                    ]
                };
            })
        }, 1500);

        this.interval = Number(interval);
    },
    setup() {
        const nodeID = ref<string>('');
        const loaded = ref<boolean>(false);
        const interval = ref<number>(0);
        const chartData = shallowRef<ChartData>({ labels: [], datasets: [] });
        return { nodeID, loaded, interval, chartOptions, chartData };
    }
})
</script>

<style scoped lang="scss">
.network-tx-chart {
    padding: 12px;
    border: 1.5px solid rgb(223, 223, 223);
    border-radius: 5px;
}
</style>