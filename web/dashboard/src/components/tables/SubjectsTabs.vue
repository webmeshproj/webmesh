<template>
  <div>
    <q-splitter v-model="splitterModel">
      <template v-slot:before>
        <q-tabs v-model="tab" vertical dense class="text-teal">
          <q-tab name="nodes" icon="computer" label="Nodes" />
          <q-tab name="users" icon="person" label="Users" />
          <q-tab name="groups" icon="group" label="Groups" />
        </q-tabs>
      </template>

      <template v-slot:after>
        <q-tab-panels
          v-model="tab"
          animated
          swipeable
          vertical
          transition-prev="jump-up"
          transition-next="jump-up"
        >
          <q-tab-panel name="nodes">
            <div class="text-subtitle1 q-mb-sm">Nodes</div>
            <q-list>
              <q-item dense v-for="node in nodes" :key="node">
                <q-item-section>
                  <q-item-label caption>{{ node }}</q-item-label>
                </q-item-section>
              </q-item>
              <q-item v-if="nodes.length == 0">
                <q-item-section>
                  <q-item-label caption>None</q-item-label>
                </q-item-section>
              </q-item>
            </q-list>
          </q-tab-panel>

          <q-tab-panel name="users">
            <div class="text-subtitle1 q-mb-sm">Users</div>
            <q-list>
              <q-item dense v-for="user in users" :key="user">
                <q-item-section>
                  <q-item-label caption>{{ user }}</q-item-label>
                </q-item-section>
              </q-item>
              <q-item v-if="users.length == 0">
                <q-item-section>
                  <q-item-label caption>None</q-item-label>
                </q-item-section>
              </q-item>
            </q-list>
          </q-tab-panel>

          <q-tab-panel name="groups">
            <div class="text-subtitle1 q-mb-sm">Groups</div>
            <q-list>
              <q-item dense v-for="group in groups" :key="group">
                <q-item-section>
                  <q-item-label caption>{{ group }}</q-item-label>
                </q-item-section>
              </q-item>
              <q-item v-if="groups.length == 0">
                <q-item-section>
                  <q-item-label caption>None</q-item-label>
                </q-item-section>
              </q-item>
            </q-list>
          </q-tab-panel>
        </q-tab-panels>
      </template>
    </q-splitter>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';
import {
  Subject,
  SubjectType,
} from '@buf/tinyzimmer_webmesh-api.grpc_web/v1/rbac_pb';

export default defineComponent({
  name: 'SubjectsTabs',
  props: {
    subjects: {
      type: Array<Subject>,
      required: true,
    },
  },
  computed: {
    nodes(): string[] {
      const out: string[] = [];
      this.subjects.forEach((s) => {
        if (
          s.getType() == SubjectType.SUBJECT_NODE ||
          s.getType() == SubjectType.SUBJECT_ALL
        ) {
          out.push(s.getName());
        }
      });
      return out;
    },
    users(): string[] {
      const out: string[] = [];
      this.subjects.forEach((s) => {
        if (
          s.getType() == SubjectType.SUBJECT_USER ||
          s.getType() == SubjectType.SUBJECT_ALL
        ) {
          out.push(s.getName());
        }
      });
      return out;
    },
    groups(): string[] {
      const out: string[] = [];
      this.subjects.forEach((s) => {
        if (
          s.getType() == SubjectType.SUBJECT_GROUP ||
          s.getType() == SubjectType.SUBJECT_ALL
        ) {
          out.push(s.getName());
        }
      });
      return out;
    },
  },
  setup() {
    return {
      tab: ref('nodes'),
      splitterModel: ref(10),
    };
  },
});
</script>
