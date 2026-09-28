// Chaque test vérifie une promesse faite sur https://vigirib.com/securite/.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import {mkdtempSync,readdirSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {ouvrirImap} from '../lib/imap.mjs';
import {traiterReception,trouverClient,deballer,authentifie} from '../lib/reception.mjs';
import {creerRegistre} from '../lib/registre.mjs';
import {avecCle,extraire} from '../lib/iban.mjs';
import {lireEml} from '../lib/eml.mjs';
import {creerAlerteMail} from '../lib/alerte-mail.mjs';
import {chiffrer,bloc,chiffrerListe} from '../navigateur/chiffrement.js';
import {dechiffrer} from '../outils/dechiffrer.mjs';
import {dechiffrerListes} from '../outils/importer-ibans.mjs';

// Faux serveur IMAP qui note toutes les commandes reçues.
function serveur(mails){
  const boite=mails.map((m,i)=>({uid:i+1,brut:Buffer.from(m),supprime:false})),commandes=[];
  const s=net.createServer(c=>{c.write('* OK\r\n');let t='';
    c.on('data',d=>{t+=d.toString('latin1');let i;
      while((i=t.indexOf('\r\n'))>=0){const l=t.slice(0,i);t=t.slice(i+2);const [tag,...r]=l.split(' '),cmd=r.join(' ');commandes.push(cmd);
        const vivants=boite.filter(m=>!m.supprime);
        if(/^LOGIN/.test(cmd))c.write(`${tag} OK\r\n`);
        else if(/^(SELECT|EXAMINE)/.test(cmd))c.write(`* OK [UIDVALIDITY 1]\r\n${tag} OK\r\n`);
        else if(/^UID SEARCH/.test(cmd))c.write(`* SEARCH ${vivants.map(m=>m.uid).join(' ')}\r\n${tag} OK\r\n`);
        else if(/^UID FETCH/.test(cmd)){const u=Number(/\d+/.exec(cmd)[0]),m=boite[u-1];c.write(`* ${u} FETCH (UID ${u} BODY[] {${m.brut.length}}\r\n`);c.write(m.brut);c.write(`)\r\n${tag} OK\r\n`);}
        else if(/^UID STORE (\d+)/.test(cmd)){boite[Number(/\d+/.exec(cmd)[0])-1].supprime=true;c.write(`${tag} OK\r\n`);}
        else if(/^EXPUNGE/.test(cmd))c.write(`${tag} OK\r\n`);
        else if(/^LOGOUT/.test(cmd)){c.write(`* BYE\r\n${tag} OK\r\n`);c.end();}
        else c.write(`${tag} BAD\r\n`);}});});
  return new Promise(ok=>s.listen(0,'127.0.0.1',()=>ok({s,boite,commandes,port:s.address().port})));
}
const connexion=(port,x={})=>({hote:'127.0.0.1',port,securise:false,utilisateur:'u',motDePasse:'p',...x});
const IBAN=avecCle('FR','30004000031234567890143');

test('promesse : la boîte d’un client est ouverte en lecture seule, toute écriture est refusée avant le serveur', async () => {
  const {s,commandes,port}=await serveur(['From: a@b.test\r\nSubject: x\r\n\r\ncorps\r\n']);
  try{
    const b=await ouvrirImap(connexion(port));
    for(const c of ['SELECT INBOX','UID STORE 1 +FLAGS (\\Deleted)','EXPUNGE','UID FETCH 1 (BODY[])','APPEND INBOX {3}','UID MOVE 1 Trash'])
      assert.throws(()=>b.commande(c),/lecture seule/);
    await assert.rejects(b.supprimer(1),/lecture seule/);
    await b.fermer();
    assert.ok(commandes.some(c=>c.startsWith('EXAMINE')));
    assert.ok(!commandes.some(c=>/^(SELECT|UID STORE|EXPUNGE|APPEND|UID MOVE)/.test(c)));
  }finally{s.close();}
});

test('promesse : chaque mail transféré est supprimé de notre boîte juste après l’analyse, et rien de son contenu n’est gardé', async () => {
  const mails=[
    `From: factures@fournisseur.test\r\nTo: compta@client.test\r\nSubject: Facture 12\r\n\r\nReglement par virement : ${IBAN}\r\n`,
    `From: promo@pub.test\r\nTo: analyse@vigirib.test\r\nSubject: Offre\r\n\r\nPublicite\r\n`,
  ];
  const {s,boite,port}=await serveur(mails),dossier=mkdtempSync(join(tmpdir(),'noyau-'));
  const vus=[];
  const analyser=async(mail,registre)=>{vus.push(mail.objet);return {niveau:'ok',raisons:[],ibans:extraire(mail.texte),org:'fournisseur.test'};};
  const memoriser=(mail,verdict,registre)=>{registre.vu(verdict.org,'2026-09-26');for(const i of verdict.ibans)registre.confirmer(verdict.org,i,'2026-09-26');};
  try{
    const b=await ouvrirImap(connexion(port,{proprietaire:true}));
    const bilan=await traiterReception({boite:b,dossier,analyser,memoriser,envoyer:async()=>{},
      clients:[{nom:'client',boites:['compta@client.test'],cle:'ab'.repeat(32),alertes:['dg@client.test']}]});
    await b.fermer();
    assert.deepEqual(vus,['Facture 12'],'seul le mail du client est analysé');
    assert.equal(bilan.ignores,1);
    assert.ok(boite.every(m=>m.supprime),'les deux copies sont supprimées, analysée ou non');
    const stocke=readdirSync(join(dossier,'client')).map(f=>readFileSync(join(dossier,'client',f),'utf8')).join('');
    assert.ok(!stocke.includes(IBAN.slice(4,20)),'aucun IBAN en clair');
    assert.ok(!stocke.includes('Facture 12')&&!stocke.includes('Reglement'),'aucun contenu de mail');
  }finally{s.close();}
});

test('promesse : un tiers ne peut pas déclencher d’alerte chez un client, ni recevoir de réponse sans authentification', () => {
  const tiers=`From: escroc@autre.test\r\nSubject: TR: facture\r\n\r\n---------- Forwarded message ---------\r\nDe : Fournisseur <f@fournisseur.test>\r\nSubject: facture\r\nTo: <compta@client.test>\r\n\r\nIBAN ${IBAN}\r\n`;
  assert.equal(trouverClient(deballer(lireEml(tiers)),[{nom:'client',boites:['client.test']}]),null);
  assert.ok(!authentifie({de:'patron@client.test',entetes:{'authentication-results':'auth=pass smtp.auth=escroc@autre.test'}}));
});

test('promesse : aucun IBAN n’est stocké en clair, l’empreinte dépend d’une clé propre à chaque entreprise', () => {
  const a=creerRegistre(null,{cle:Buffer.alloc(32,1)}),b=creerRegistre(null,{cle:Buffer.alloc(32,2)});
  for(const r of [a,b]){r.vu('f.test','d');r.confirmer('f.test',IBAN,'d');}
  assert.ok(!JSON.stringify(a.etat).includes(IBAN.slice(4,20)));
  assert.notDeepEqual(Object.keys(a.etat.fournisseurs['f.test'].ibans),Object.keys(b.etat.fournisseurs['f.test'].ibans));
});

test('promesse : codes d’accès et IBAN de référence sont chiffrés dans le navigateur, seul Vigirib les lit', async () => {
  const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:4096,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
  const secret='Code-Tres-Secret-42';
  const b1=bloc(await chiffrer({hote:'imap.exemple.test',port:993,utilisateur:'compta@client.test',motDePasse:secret,boite:'INBOX'},publicKey));
  assert.ok(!b1.includes(secret));assert.equal(dechiffrer(b1,privateKey).motDePasse,secret);
  const b2=await chiffrerListe({entreprise:'Client',ibans:[IBAN]},publicKey);
  assert.ok(!b2.includes(IBAN.slice(4,20)));assert.deepEqual(dechiffrerListes(b2,privateKey)[0].ibans,[IBAN]);
});

test('promesse : une alerte ne contient jamais d’IBAN complet', async () => {
  const envois=[];const envoyer=async m=>{envois.push(m);};
  const alerte=creerAlerteMail({destinataires:'dg@client.test',hote:'h',utilisateur:'u',motDePasse:'p',envoyer});
  await alerte({niveau:'alerte',raisons:['IBAN nouveau pour f.test (FR76 … 0143), différent de FR12 … 0101'],ibans:[IBAN]},{de:'f@f.test',objet:'Facture'});
  assert.equal(envois.length,1);assert.ok(!envois[0].texte.includes(IBAN));
});

test('promesse : les secrets déchiffrés partent au serveur par l’entrée standard de SSH, sans fichier local ni écrasement', async () => {
  const {deposerClient,surLeServeur}=await import('../outils/serveur.mjs');
  const {EventEmitter}=await import('node:events');
  const appels=[];
  const executer=code=>(cmd,args)=>{const p=new EventEmitter();p.stdin={end:d=>{appels.push({cmd,args,entree:d});setImmediate(()=>p.emit('close',code));}};return p;};
  await deposerClient('client','IMAP_MOT_DE_PASSE=secret\n',{serveur:'vigi',executer:executer(0)});
  assert.equal(appels[0].cmd,'ssh');
  assert.match(appels[0].args[1],/^umask 077;.*if \[ -e ~\/\.vigi\/clients\/client\.env \].*exit 3; fi; cat > ~\/\.vigi\/clients\/client\.env$/);
  assert.doesNotMatch(appels[0].args[1],/secret/,'jamais sur la ligne de commande');
  assert.equal(appels[0].entree,'IMAP_MOT_DE_PASSE=secret\n');
  assert.throws(()=>deposerClient('../x; rm -rf ~','x',{executer:executer(0)}),/invalide/);
  await assert.rejects(surLeServeur('true','x',{executer:executer(3)}),/refusé/);
});

test('promesse : la mémoire des IBAN est lisible par le seul compte du service (0600)', async () => {
  const {statSync,writeFileSync}=await import('node:fs');
  const f=join(mkdtempSync(join(tmpdir(),'noyau-droits-')),'registre.json');
  writeFileSync(f,'{"fournisseurs":{}}',{mode:0o664});
  const r=creerRegistre(f,{cle:Buffer.alloc(32,3)});r.vu('f.test','d');r.sauver();
  assert.equal(statSync(f).mode&0o777,0o600);
});

test('promesse : un mail usurpé ne passe pas pour authentifié (en-tête forgé, ARC, domaine qui ne correspond pas)', () => {
  const brut='Authentication-Results: mx.mail.ovh.net; spf=softfail smtp.mailfrom=escroc.test; dmarc=fail header.from=victime.test\r\n'
    +'Received: from escroc.test\r\nAuthentication-Results: mx.mail.ovh.net; dmarc=pass header.from=victime.test\r\n'
    +'From: <patron@victime.test>\r\nSubject: TR: facture\r\n\r\nx\r\n';
  assert.ok(!authentifie(lireEml(brut)),'seul l’en-tête posé par notre serveur, le plus haut, compte');
  const m=(de,ar,k='authentication-results')=>({de,entetes:{[k]:ar}});
  assert.ok(!authentifie(m('patron@victime.test','mx.mail.ovh.net; spf=pass smtp.mailfrom=escroc.test')),'SPF valide pour un autre domaine');
  assert.ok(!authentifie(m('patron@victime.test','i=1; mx.mail.ovh.net; dkim=pass header.d=victime.test','arc-authentication-results')),'ARC ignoré');
  assert.ok(authentifie(m('patron@victime.test','mx.mail.ovh.net; dmarc=pass header.from=victime.test')),'DMARC aligné accepté');
});

test('promesse : inscription seulement par le titulaire authentifié, désinscription qui efface tout', async () => {
  const {gestionInscriptions}=await import('../lib/inscriptions.mjs');
  const {existsSync}=await import('node:fs');
  const racine=mkdtempSync(join(tmpdir(),'noyau-inscr-')),dossierClients=join(racine,'clients'),dossier=join(racine,'donnees');
  const g=gestionInscriptions({dossierClients,dossier});
  const faux=`From: <patron@victime.test>\r\nTo: analyse@vigirib.test\r\nAuthentication-Results: mx.mail.ovh.net; spf=pass smtp.mailfrom=escroc.test\r\nSubject: inscription\r\n\r\nx\r\n`;
  const vrai=`From: <compta@client.test>\r\nTo: analyse@vigirib.test\r\nAuthentication-Results: mx.mail.ovh.net; dmarc=pass header.from=client.test\r\nSubject: inscription\r\n\r\nx\r\n`;
  const {s,port}=await serveur([faux,vrai]);const envois=[];
  const analyser=async()=>({niveau:'ok',raisons:[],ibans:[],org:''}),memoriser=()=>{};
  try{
    const b=await ouvrirImap(connexion(port,{proprietaire:true}));
    await traiterReception({boite:b,clients:[],dossier,analyser,memoriser,envoyer:async m=>{envois.push(m);},adresseReception:'analyse@vigirib.test',inscrire:g.inscrire,desinscrire:g.desinscrire});
    await b.fermer();
  }finally{s.close();}
  assert.ok(!existsSync(join(dossierClients,'patron-victime-test.env')),'rien pour une adresse usurpée');
  assert.ok(!envois.some(m=>m.a[0]==='patron@victime.test'),'aucune réponse à une adresse usurpée');
  assert.ok(existsSync(join(dossierClients,'compta-client-test.env')));
  assert.ok(g.desinscrire('compta@client.test').ok);
  assert.ok(!existsSync(join(dossierClients,'compta-client-test.env'))&&!existsSync(join(dossier,'compta-client-test')),'configuration et mémoire effacées');
});

