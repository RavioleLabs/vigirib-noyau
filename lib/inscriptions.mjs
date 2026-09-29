// Inscription et désinscription en libre-service, par un simple mail à la boîte de réception (voir reception.mjs).
// La configuration du client est écrite sur le serveur, lisible par le seul compte du service ; la désinscription efface
// la configuration ET la mémoire des IBAN, tout de suite. Aucune donnée ne sort du serveur ici.
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {readFileSync,writeFileSync,mkdirSync,existsSync,readdirSync,unlinkSync,rmSync} from 'node:fs';
import {parseEnv} from 'node:util';

// Un mois offert depuis le 29/09 ; `dureePour(email)` peut accorder plus (trois mois promis aux premiers prospects).
export const DUREE_ESSAI_MOIS=1;
const NOM=/^[a-z0-9-]+$/;
export const slug=s=>String(s||'client').normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')||'client';
const propre=v=>String(v??'').replace(/[\r\n#]/g,' ').trim();
const boitesDe=c=>String(c.VIGI_BOITES||'').toLowerCase().split(/[,;\s]+/).filter(Boolean);

// Plafonds : 30 inscriptions par jour, 5 boîtes par domaine ; au-delà, l'inscription attend l'éditeur.
export function gestionInscriptions({dossierClients,dossier,maxParJour=30,maxParDomaine=5,maintenant=()=>new Date(),dureePour=()=>DUREE_ESSAI_MOIS}){
  const tous=()=>(existsSync(dossierClients)?readdirSync(dossierClients):[]).filter(f=>f.endsWith('.env')&&NOM.test(f.slice(0,-4)))
    .map(f=>({nom:f.slice(0,-4),c:{...parseEnv(readFileSync(join(dossierClients,f),'utf8'))}}));
  return {
    inscrire({email,entreprise,alertes}){
      email=String(email||'').toLowerCase();
      if(!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/.test(email))return {refus:'adresse invalide'};
      mkdirSync(dossierClients,{recursive:true,mode:0o700});
      const liste=tous(),deja=liste.find(x=>boitesDe(x.c).includes(email));
      if(deja)return {ok:true,deja:true,nom:deja.nom,alertes:String(deja.c.VIGI_ALERTE_MAIL||'').split(',').filter(Boolean),essaiJusqua:deja.c.VIGI_ESSAI_JUSQUA||null};
      const t=maintenant(),jour=t.toISOString().slice(0,10),dom=email.split('@')[1];
      if(liste.filter(x=>String(x.c.VIGI_ACTIF_DEPUIS||'').startsWith(jour)).length>=maxParJour)return {refus:'plafond du jour atteint'};
      if(liste.filter(x=>boitesDe(x.c).some(b=>b.endsWith('@'+dom))).length>=maxParDomaine)return {refus:'plafond du domaine atteint'};
      const nom=slug(email),fin=new Date(t);fin.setMonth(fin.getMonth()+(Number(dureePour(email))||DUREE_ESSAI_MOIS));
      const cle=randomBytes(32).toString('hex'),essaiJusqua=fin.toISOString().slice(0,10),a=(alertes?.length?alertes:[email]).map(x=>String(x).toLowerCase());
      try{
        writeFileSync(join(dossierClients,nom+'.env'),[`# ${propre(entreprise)}, inscription par mail le ${t.toISOString()}`,
          `VIGI_ENTREPRISE=${propre(entreprise)}`,`VIGI_BOITES=${email}`,`VIGI_ALERTE_MAIL=${a.join(',')}`,`VIGI_CLE=${cle}`,
          `VIGI_ACTIF_DEPUIS=${t.toISOString()}`,`VIGI_ESSAI_JUSQUA=${essaiJusqua}`,
          // Pas d'analyse par un service externe pendant l'essai (conditions de l'essai) : aucun texte de mail ne quitte OVHcloud.
          'VIGI_JEV=0',''].join('\n'),{mode:0o600,flag:'wx'});
      }catch{return {refus:'configuration déjà présente'};}
      return {ok:true,nom,essaiJusqua,alertes:a,client:{nom,boites:[email],cle,alertes:a,actifDepuis:t.toISOString(),jev:false}};
    },
    desinscrire(email){
      email=String(email||'').toLowerCase();
      const x=tous().find(x=>boitesDe(x.c).includes(email));
      if(!x)return {ok:false};
      unlinkSync(join(dossierClients,x.nom+'.env'));
      rmSync(join(dossier,x.nom),{recursive:true,force:true});
      return {ok:true,nom:x.nom};
    },
  };
}
