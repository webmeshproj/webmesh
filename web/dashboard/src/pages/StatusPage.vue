<template>
  <q-page class="q-pa-md row">
    <q-inner-loading :showing="!loaded">
      <q-spinner-gears size="10em" color="primary" />
    </q-inner-loading>
    <div v-if="loaded" class="row justify-evenly items-center">
      <div class="col-6">
        <network-transmission-chart-container />
      </div>
      <div class="q-pl-md q-pt-md col-6">
        <q-card dark bordered class="bg-grey-9 column">
          <q-card-section>
            <q-icon name="router" size="lg" />
            <div class="text-h6">System</div>
          </q-card-section>
          <q-separator dark inset />
          <q-card-section>
            <div>
              <strong>Uptime: </strong
              >{{ nodeStatus?.getUptime().split('.')[0] + 's' }}
            </div>
            <div>
              <strong>Interface: </strong
              >{{ nodeStatus?.getInterfaceMetrics()?.getDeviceName() }}
            </div>
            <div>
              <strong>Type: </strong
              >{{ nodeStatus?.getInterfaceMetrics()?.getType() }}
            </div>
            <div>
              <strong>Public Key: </strong
              >{{ nodeStatus?.getInterfaceMetrics()?.getPublicKey() }}
            </div>
            <div>
              <strong>Cluster IPv4: </strong
              >{{ nodeStatus?.getInterfaceMetrics()?.getAddressV4() }}
            </div>
            <div>
              <strong>Cluster IPv6: </strong
              >{{ nodeStatus?.getInterfaceMetrics()?.getAddressV6() }}
            </div>
            <div>
              <strong>Cluster Status: </strong
              ><ClusterStatus
                v-if="nodeStatus"
                :status="nodeStatus?.getClusterStatus()"
              />
            </div>
            <div class="q-pa-md"><q-separator dark inset /></div>
            <div><strong>Version: </strong>{{ nodeStatus?.getVersion() }}</div>
            <div><strong>Commit: </strong>{{ nodeStatus?.getCommit() }}</div>
            <div>
              <strong>Build Date: </strong>{{ nodeStatus?.getBuildDate() }}
            </div>
          </q-card-section>
        </q-card>
      </div>
      <div class="col-6"></div>
      <div class="col-6">
        <q-card dark bordered class="bg-grey-9">
          <q-card-section>
            <q-icon name="hub" size="lg" />
            <div class="text-h6">Peers</div>
          </q-card-section>
          <q-separator dark inset />
          <q-card-section>
            <div
              v-for="(peer, idx) in nodeStatus
                ?.getInterfaceMetrics()
                ?.getPeersList()"
              :key="idx"
            >
              <div><strong>Public Key: </strong>{{ peer.getPublicKey() }}</div>
              <div>
                <strong>Last Handshake: </strong
                >{{ peer.getLastHandshakeTime() }}
              </div>
              <div>
                <strong>Allowed IPs: </strong
                >{{ peer.getAllowedIpsList().join(', ') }}
              </div>
              <div>
                <strong>TX Bytes: </strong>{{ peer.getTransmitBytes() }}
              </div>
              <div><strong>RX Bytes: </strong>{{ peer.getReceiveBytes() }}</div>
              <div class="q-pa-md"><q-separator dark inset /></div>
            </div>
          </q-card-section>
        </q-card>
      </div>
    </div>
  </q-page>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';
import { useQuasar } from 'quasar';
import { useClientStore } from 'stores/client-store';

import { Status } from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/node_pb';
import AuthDialog from 'src/components/AuthDialog.vue';
import ClusterStatus from 'src/components/ClusterStatus.vue';
import NetworkTransmissionChartContainer from 'src/components/charts/NetworkTransmissionChartContainer.vue';

export default defineComponent({
  name: 'StatusPage',
  components: { NetworkTransmissionChartContainer, ClusterStatus },
  setup() {
    const $q = useQuasar();
    const loaded = ref<boolean>(false);
    const nodeStatus = ref<Status>();
    const clients = useClientStore();
    clients.authenticated.then((authenticated: boolean) => {
      if (authenticated) {
        clients.serverStatus.then((status: Status) => {
          nodeStatus.value = status;
        });
        loaded.value = true;
        return;
      }
      $q.dialog({
        component: AuthDialog,
      }).onOk(() => {
        clients.serverStatus.then((status: Status) => {
          nodeStatus.value = status;
        });
        loaded.value = true;
        return;
      });
    });
    return { loaded, nodeStatus };
  },
});
</script>
