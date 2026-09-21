import {createApp} from 'vue'
import App from './App.vue'

import './assets/main.css'
import {createRouter, createWebHistory} from "vue-router";
import State from "@/State.vue";
import Flags from "@/Flags.vue";
import AutoRoute from "@/AutoRoute.vue";
import Processes from "@/Processes.vue";

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {path: '/', component: AutoRoute},
        {path: '/state', component: State},
        {path: '/flags', component: Flags},
        {path: '/processes/:macAddress', component: Processes},
    ]
})
createApp(App).use(router).mount('#app')
