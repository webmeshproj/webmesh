<template>
    <ChartLine id="network-tx-chart" :data="data" :options="options" />
</template>

<script lang="ts">
import { defineComponent } from 'vue';
import { Line as ChartLine } from 'vue-chartjs';
import { 
    Chart as ChartJS,
    LineElement,
    Title,
    Tooltip,
    Legend,
    CategoryScale,
    LinearScale,
    TimeScale,
    PointElement,
    TimeSeriesScale,
    Filler
} from 'chart.js'

ChartJS.register(
    Title,
    Tooltip,
    Legend,
    LineElement,
    CategoryScale,
    LinearScale,
    TimeScale,
    TimeSeriesScale,
    PointElement,
    Filler
);

export interface ChartData {
    labels: string[];
    datasets: {
        label: string;
        data: number[];
        borderColor: string;
        backgroundColor: string;
        fill: boolean;
        cubicInterpolationMode: string;
        tension: number;
    }[];
}

export default defineComponent({
    name: 'NetworkTransmissionChart',
    components: { ChartLine },
    props: {
        data: {
            type: Object as () => ChartData,
            default: null
        },
        options: {
            type: Object,
            default: null
        }
    },
});
</script>
