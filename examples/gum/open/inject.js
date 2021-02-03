const frida = require('frida');
const fs = require('fs');
const { promisify } = require('util');

const readFile = promisify(fs.readFile);

const [ target, libraryPath ] = process.argv.slice(2);

let device = null;

async function main() {
  const libraryBlob = await readFile(libraryPath);

  device = await frida.getLocalDevice();
  device.uninjected.connect(onUninjected);

  try {
    const id = await device.injectLibraryBlob(parseInt(target), libraryBlob, 'example_agent_main', 'w00t');
    console.log('[*] Injected id:', id);
  } catch (e) {
    device.uninjected.disconnect(onUninjected);
    throw e;
  }
}

function onUninjected(id) {
  console.log('[*] onUninjected() id:', id);
  device.uninjected.disconnect(onUninjected);
}

main()
  .catch(e => {
    console.error(e);
  });
