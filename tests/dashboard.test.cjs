const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

class Element{
 constructor(){this.value='';this.textContent='';this.children=[];this.style={};this.events={};this.hidden=false;}
 append(...children){this.children.push(...children);}
 replaceChildren(...children){this.children=children;}
 addEventListener(name,handler){this.events[name]=handler;}
 showModal(){} close(){}
}
function dashboard(fetch){
 const nodes=new Map();
 const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id);},createElement(){return new Element();}};
 const storage=new Map();
 const context=vm.createContext({document,console,URL,URLSearchParams,AbortController,Date,Map,Error,TypeError,Promise,
  fetch:fetch||(()=>{throw Error('Unexpected network call');}),setTimeout,clearTimeout,setInterval:()=>{},
  window:{addEventListener(){},open(){}},localStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)}});
 document.getElementById('filter').value='all';document.getElementById('sort').value='charge';
 const html=fs.readFileSync(path.join(__dirname,'..','dashboard.html'),'utf8');
 vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1],context);
 return {context,nodes,run:code=>vm.runInContext(code,context),storage};
}
function sample(overrides={}){
 return {schema:'windows-class-monitoring/v1',device_id:'sample',computer_name:'PC1',display_name:'Ноутбук',
  battery_percent:15,battery_present:true,charging:false,ac_connected:false,interval_seconds:300,
  agent_version:'1.0.0',measured_at:new Date().toISOString(),...overrides};
}
test('low charge only requires attention with fresh data and known disconnected AC',()=>{
 const app=dashboard();app.context.data=sample();
 assert.equal(app.run('needsPower(data)'),true);
 app.context.data=sample({ac_connected:true});assert.equal(app.run('needsPower(data)'),false);
 app.context.data=sample({ac_connected:null});assert.equal(app.run('needsPower(data)'),false);
 app.context.data=sample({measured_at:new Date(Date.now()-3600000).toISOString()});assert.equal(app.run('needsPower(data)'),false);
});
test('stale threshold accommodates configured collection interval',()=>{
 const app=dashboard();app.context.data=sample({interval_seconds:3600,measured_at:new Date(Date.now()-3600000).toISOString()});
 assert.equal(app.run('stale(data)'),false);
 app.context.data=sample({read_error:'network'});assert.equal(app.run('stale(data)'),true);
});
test('malformed cloud data is rejected instead of breaking all cards',()=>{
 const app=dashboard();
 for(const data of [sample({battery_percent:255}),sample({ac_connected:'yes'}),sample({display_name:{}}),sample({measured_at:'bad'})]){
  app.context.data=data;assert.throws(()=>app.run('validateDevice(data)'));
 }
 app.context.data=sample({battery_percent:null});assert.doesNotThrow(()=>app.run('validateDevice(data)'));
});
test('device names render as text, including HTML-like values',()=>{
 const app=dashboard();app.context.data=sample({display_name:'<img src=x onerror=alert(1)>'});
 app.run('devices=[data];render()');
 const card=app.nodes.get('grid').children[0];
 assert.equal(card.children[0].children[0].children[0].textContent,'<img src=x onerror=alert(1)>');
});
test('list pagination collects every device and skips non-JSON files',async()=>{
 const urls=[];
 const app=dashboard(async url=>{urls.push(url);const offset=Number(new URL(url).searchParams.get('offset'));return {ok:true,json:async()=>({type:'dir',_embedded:{total:101,items:offset===0?Array.from({length:100},(_,i)=>({type:'file',name:i===0?'note.txt':i+'.json'})):[{type:'file',name:'last.json'}]}})};});
 const files=await app.run("listFiles('secret','app:/wcm/devices')");
 assert.equal(files.length,100);assert.equal(urls.length,2);assert.equal(new URL(urls[1]).searchParams.get('offset'),'100');
});
test('API errors are surfaced without signed URLs',async()=>{
 const app=dashboard(async()=>({ok:false,status:401}));
 await assert.rejects(app.run("request('https://example.test/?secret=hidden','token')"),/Токен/);
});
test('signed download request has no OAuth header',async()=>{
 let options;const app=dashboard(async(url,opts)=>{options=opts;return {ok:true,json:async()=>({})};});
 await app.run("request('https://download.example.test/signed')");
 assert.equal(options.headers.Authorization,undefined);
});
test('failed device download preserves previous data and marks it stale',async()=>{
 const app=dashboard(async url=>{
  if(new URL(url).pathname.endsWith('/download'))return {ok:false,status:503};
  return {ok:true,json:async()=>({type:'dir',_embedded:{total:1,items:[{type:'file',name:'d.json',path:'app:/wcm/devices/d.json',modified:'new'}]}})};
 });
 app.context.data=sample();
 app.run("token='secret';diskPath='app:/wcm/devices';cache.set('app:/wcm/devices/d.json',{etag:'old',data});");
 await app.run('refresh()');
 assert.equal(app.run('devices.length'),1);assert.equal(app.run('devices[0].battery_percent'),15);assert.equal(app.run('stale(devices[0])'),true);
});
test('invalid path cannot escape app folder',()=>{
 const app=dashboard();
 for(const candidate of ['disk:/private','app:/','app:/a/../b','app:/a//b','app:/a\\b']){
  app.context.path=candidate;assert.equal(app.run('validatePath(path)'),false);
 }
});
test('disconnected tab discards an in-flight refresh',async()=>{
 let release;const app=dashboard(()=>new Promise(resolve=>{release=()=>resolve({ok:true,json:async()=>({type:'dir',_embedded:{items:[],total:0}})});}));
 app.run("token='secret'");const waiting=app.run('refresh()');app.run('disconnect()');release();await waiting;
 assert.equal(app.run('token'),'');assert.equal(app.run('devices.length'),0);
 assert.equal(app.nodes.get('status').textContent,'Ожидание подключения');
});
