const srv = "http://10.132.35.254/cgi-bin/";
let config = null;
export default {
    server: srv,
    async load() {
        return config || (config = await (await fetch(srv + 'config')).json());
    },
    async save(mac, conf) {
        config.knownDevices[mac] = conf;
        await fetch(srv + 'config', {
            method: 'POST',
            body: JSON.stringify(config),
        });
    }
};
  