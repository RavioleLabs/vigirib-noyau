// Client SMTP minimal, sans dépendance : TLS implicite (port 465, OVHcloud ssl0.ovh.net), AUTH PLAIN, un message.
// Sert aux alertes par mail. Le mot de passe ne figure jamais dans les erreurs.
import tls from 'node:tls';
import net from 'node:net';

const b64=s=>Buffer.from(s,'utf8').toString('base64');
const mot=s=>/^[\x20-\x7e]*$/.test(s)?s:`=?UTF-8?B?${b64(s)}?=`;
const adresse=a=>(/<([^>]+)>/.exec(a)?.[1]||a).trim();

// Construit le message : texte brut UTF-8 en base64, en-têtes encodés.
export function construireMessage({de,a,sujet,texte,domaine='vigirib.com'}){
  const nomDe=/^(.*)<[^>]+>$/.exec(de)?.[1]?.trim().replace(/^"|"$/g,'');
  const entetes=[
    `From: ${nomDe?`${mot(nomDe)} <${adresse(de)}>`:`<${adresse(de)}>`}`,
    `To: ${a.map(x=>`<${adresse(x)}>`).join(', ')}`,
    `Subject: ${mot(sujet)}`,
    `Date: ${new Date().toUTCString().replace('GMT','+0000')}`,
    `Message-ID: <${crypto.randomUUID()}@${domaine}>`,
    'MIME-Version: 1.0','Content-Type: text/plain; charset=UTF-8','Content-Transfer-Encoding: base64',
  ];
  return entetes.join('\r\n')+'\r\n\r\n'+b64(texte).replace(/.{1,76}/g,'$&\r\n');
}

export async function envoyerMail({hote,port=465,securise=true,utilisateur,motDePasse,de,a,sujet,texte,delaiMs=20000}){
  if(!a?.length)throw Error('SMTP : aucun destinataire');
  const sock=securise?tls.connect({host:hote,port,servername:hote}):net.connect({host:hote,port});
  sock.setTimeout(delaiMs,()=>sock.destroy(Error('SMTP : délai dépassé')));
  let tampon='',attente=null;
  // Une réponse SMTP peut tenir sur plusieurs lignes (« 250-… » puis « 250 … »).
  sock.on('data',d=>{tampon+=d.toString('latin1');
    const lignes=tampon.split('\r\n');
    const fin=lignes.findIndex(l=>/^\d{3} /.test(l));
    if(fin>=0&&attente){const rep=lignes.slice(0,fin+1).join('\n');tampon=lignes.slice(fin+1).join('\r\n');const f=attente;attente=null;f.ok(rep);}
  });
  sock.on('error',e=>{attente?.ko(e);attente=null;});
  const lire=()=>new Promise((ok,ko)=>{attente={ok,ko};});
  const etape=async(commande,code,libelle)=>{
    if(commande!==null)sock.write(commande+'\r\n');
    const rep=await lire();
    if(!rep.startsWith(String(code)))throw Error(`SMTP : ${libelle} refusé (${rep.split('\n').at(-1).slice(0,120)})`);
    return rep;
  };
  try{
    await etape(null,220,'accueil');
    await etape(`EHLO ${adresse(de).split('@')[1]||'localhost'}`,250,'EHLO');
    await etape(`AUTH PLAIN ${b64(`\0${utilisateur}\0${motDePasse}`)}`,235,'authentification');
    await etape(`MAIL FROM:<${adresse(de)}>`,250,'expéditeur');
    for(const x of a)await etape(`RCPT TO:<${adresse(x)}>`,250,'destinataire');
    await etape('DATA',354,'DATA');
    const corps=construireMessage({de,a,sujet,texte,domaine:adresse(de).split('@')[1]}).replace(/^\./gm,'..');
    await etape(corps+'\r\n.',250,'message');
    sock.write('QUIT\r\n');
  }finally{sock.end();}
}
