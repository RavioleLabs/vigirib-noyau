// Client IMAP minimal, en LECTURE SEULE, sans dépendance.
// La boîte est ouverte par EXAMINE (jamais SELECT) et les mails lus par BODY.PEEK[] : rien n'est marqué lu,
// déplacé ni supprimé. Toute commande hors de la liste blanche est refusée avant d'atteindre le serveur.
import tls from 'node:tls';
import net from 'node:net';

const AUTORISEES=/^(CAPABILITY|LOGIN|EXAMINE|UID SEARCH|UID FETCH \S+ \(UID BODY\.PEEK\[\]\)|LOGOUT)(?= |$)/;
// Mode « propriétaire » : UNIQUEMENT pour la boîte de réception de Vigirib (analyse@), qui reçoit les transferts
// et doit les supprimer après analyse. Jamais pour la boîte d'un client, qui reste en lecture seule.
const AUTORISEES_PROPRIETAIRE=/^(CAPABILITY|LOGIN|SELECT|UID SEARCH|UID FETCH \S+ \(UID BODY\.PEEK\[\]\)|UID STORE \d+ \+FLAGS\.SILENT \(\\Deleted\)|EXPUNGE|LOGOUT)(?= |$)/;

const citer=s=>'"'+String(s).replace(/[\\"]/g,'\\$&')+'"';

export async function ouvrirImap({hote,port=993,securise=true,utilisateur,motDePasse,boite='INBOX',delaiMs=30000,proprietaire=false}){
  const liste=proprietaire?AUTORISEES_PROPRIETAIRE:AUTORISEES;
  const sock=securise?tls.connect({host:hote,port,servername:hote}):net.connect({host:hote,port});
  sock.setTimeout(delaiMs,()=>sock.destroy(Error('IMAP : délai dépassé')));
  let tampon=Buffer.alloc(0),attente=null,accueil=null,n=0,erreur=null;
  const reponses=[];

  // Découpe le flux en réponses : une ligne, plus d'éventuels littéraux {taille}\r\n<octets>.
  function lire(){
    for(;;){
      const fin=tampon.indexOf('\r\n');
      if(fin<0)return;
      let ligne=tampon.subarray(0,fin).toString('latin1'),pos=fin+2;const litteraux=[];
      let m;
      while((m=/\{(\d+)\}$/.exec(ligne))){
        const taille=Number(m[1]);
        if(tampon.length<pos+taille)return;
        litteraux.push(tampon.subarray(pos,pos+taille));pos+=taille;
        const suite=tampon.indexOf('\r\n',pos);
        if(suite<0)return;
        ligne+=tampon.subarray(pos,suite).toString('latin1');pos=suite+2;
      }
      tampon=tampon.subarray(pos);
      const r={ligne,litteraux};
      if(!accueil){accueil=r;attente?.();continue;}
      reponses.push(r);
      if(attente&&r.ligne.startsWith(attente.tag+' '))attente.fin();
    }
  }
  sock.on('data',d=>{tampon=Buffer.concat([tampon,d]);lire();});
  sock.on('error',e=>{erreur=e;attente?.echec?.(e);});

  await new Promise((ok,ko)=>{attente=ok;attente.echec=ko;if(accueil)ok();});
  if(!/^\* (OK|PREAUTH)/.test(accueil.ligne))throw Error('IMAP : accueil inattendu');

  function commande(texte){
    if(!liste.test(texte))throw Error(`IMAP : commande refusée ${proprietaire?'hors de la liste de la boîte Vigirib':'en lecture seule'} (${texte.split(' ')[0]})`);
    if(erreur)throw erreur;
    const tag='V'+(++n);
    reponses.length=0;
    return new Promise((ok,ko)=>{
      attente={tag,fin(){const tous=[...reponses];attente=null;
        const fin=tous.at(-1).ligne;
        if(!new RegExp(`^${tag} OK`).test(fin))ko(Error('IMAP : '+fin.replace(/LOGIN .*/,'LOGIN ***')));
        else ok(tous.slice(0,-1));},echec:ko};
      sock.write(tag+' '+texte+'\r\n');
    });
  }

  await commande(`LOGIN ${citer(utilisateur)} ${citer(motDePasse)}`);
  const ouverte=await commande(`${proprietaire?'SELECT':'EXAMINE'} ${citer(boite)}`);
  const validite=Number(/UIDVALIDITY (\d+)/.exec(ouverte.map(r=>r.ligne).join('\n'))?.[1]||0);

  return {
    validite,
    // UID des mails dont l'UID est strictement supérieur à `apres`.
    async uidsApres(apres=0){
      const r=await commande(`UID SEARCH UID ${apres+1}:*`);
      return r.flatMap(x=>/^\* SEARCH/.test(x.ligne)?x.ligne.slice(8).trim().split(/\s+/).filter(Boolean).map(Number):[])
        .filter(u=>u>apres).sort((a,b)=>a-b);
    },
    // UID des mails reçus depuis une date (premier passage : historique récent seulement).
    async uidsDepuis(date){
      const mois=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][date.getUTCMonth()];
      const r=await commande(`UID SEARCH SINCE ${date.getUTCDate()}-${mois}-${date.getUTCFullYear()}`);
      return r.flatMap(x=>/^\* SEARCH/.test(x.ligne)?x.ligne.slice(8).trim().split(/\s+/).filter(Boolean).map(Number):[]).sort((a,b)=>a-b);
    },
    async lire(uid){
      const r=await commande(`UID FETCH ${uid} (UID BODY.PEEK[])`);
      const f=r.find(x=>x.litteraux.length);
      return f?f.litteraux[0].toString('utf8'):null;
    },
    // Boîte Vigirib seulement : marque un mail supprimé, puis purge la boîte.
    async supprimer(uid){await commande(`UID STORE ${Number(uid)} +FLAGS.SILENT (\\Deleted)`);},
    async purger(){await commande('EXPUNGE');},
    commande,
    async fermer(){try{await commande('LOGOUT');}catch{}sock.end();},
  };
}
