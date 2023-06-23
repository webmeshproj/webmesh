<template>
    <div class="row">
        <div class="col col-md-8 text-h6">
            {{ title }}
            <q-btn dense flat @click="refresh">
                <q-icon name="refresh" />
            </q-btn>
        </div>
        <div class="col-6 col-md-4">
            <q-input borderless dense debounce="300" v-model="filter" placeholder="Search">
                <template v-slot:append>
                    <q-icon name="search" />
                </template>
            </q-input>
        </div>
    </div>
</template>

<script>
import { defineComponent, toRef } from 'vue';

export default defineComponent({
    name: 'TableHeader',
    props: {
        title: { 
            type: String,
            required: true
        },
        filterRef: { 
            type: String,
            required: true
        },
        refresh: { 
            type: Function,
            required: true
        },
    },
    setup(props) {
        return { filter: toRef(props, 'filterRef') };
    }
});
</script>