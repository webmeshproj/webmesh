<template>
  <div class="row items-center">
    <q-icon size="xs" :name="statusIcon" left />
    <span>{{ statusText }}</span>
  </div>
</template>
  
<script lang="ts">
import { defineComponent } from 'vue';

import { ClusterStatus } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_pb';
  
export default defineComponent({
    name: 'ClusterStatus',
    props: {
      status: {
        type: Number,
        required: true
      },
    },
    computed: {
      statusText(): string {
        switch (this.status) {
          case ClusterStatus.CLUSTER_STATUS_UNKNOWN:
            return 'Unknown';
          case ClusterStatus.CLUSTER_LEADER:
            return 'Leader';
          case ClusterStatus.CLUSTER_VOTER:
            return 'Voter';
          case ClusterStatus.CLUSTER_NON_VOTER:
            return 'Observer';
          default:
              return 'Unknown';
        };
      },
      statusIcon(): string {
        switch (this.status) {
          case ClusterStatus.CLUSTER_STATUS_UNKNOWN:
            return 'help';
          case ClusterStatus.CLUSTER_LEADER:
            return 'star';
          case ClusterStatus.CLUSTER_VOTER:
            return 'how_to_vote';
          case ClusterStatus.CLUSTER_NON_VOTER:
            return 'explore';
          default:
              return 'help';
        };
      }
    }
});
</script>
    