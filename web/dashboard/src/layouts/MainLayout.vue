<template>
  <q-layout view="lHh Lpr lFf">
    <q-header elevated>
      <q-toolbar>
        <q-btn
          flat
          dense
          round
          icon="menu"
          aria-label="Menu"
          @click="toggleLeftDrawer"
        />

        <q-toolbar-title> Webmesh Dashboard </q-toolbar-title>

        <div>Webmesh v{{ version }}</div>
      </q-toolbar>
    </q-header>

    <q-drawer v-model="leftDrawerOpen" show-if-above bordered>
      <q-list>
        <q-item-label header> Resources </q-item-label>

        <EssentialLink
          v-for="link in essentialLinks"
          :key="link.title"
          v-bind="link"
        />
      </q-list>
    </q-drawer>

    <q-page-container>
      <router-view />
    </q-page-container>
  </q-layout>
</template>

<script lang="ts">
import { defineComponent, ref } from 'vue';
import EssentialLink from 'components/EssentialLink.vue';

const linksList = [
  {
    title: 'Status',
    caption: 'System status',
    icon: 'area_chart',
    link: '#',
  },
  {
    title: 'Nodes',
    caption: 'Devices connected to the network',
    icon: 'devices_other',
    link: '#/nodes',
  },
  {
    title: 'Network',
    caption: 'Network topology',
    icon: 'device_hub',
    link: '#/network',
  },
  {
    title: 'RBAC',
    caption: 'Role-based access control',
    icon: 'security',
    link: '#/rbac',
  },
  {
    title: 'Github',
    caption: 'github.com/webmeshproj',
    icon: 'code',
    link: 'https://github.com/webmeshproj',
    target: '_blank',
  },
];

export default defineComponent({
  name: 'MainLayout',

  components: {
    EssentialLink,
  },

  setup() {
    const leftDrawerOpen = ref(false);
    const version = process.env.VERSION?.toString();
    return {
      essentialLinks: linksList,
      leftDrawerOpen,
      version,
      toggleLeftDrawer() {
        leftDrawerOpen.value = !leftDrawerOpen.value;
      },
    };
  },
});
</script>
