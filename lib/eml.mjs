// Lecture minimale d'un mail brut (.eml, RFC 5322) : en-têtes, texte, pièces jointes texte.
// Pas de dépendance : multipart, base64, quoted-printable et encodages d'en-tête =?utf-8?.
import {textePdf} from './pdf.mjs';

function decoderMot(s){
  return s.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g,(_,cs,enc,txt)=>{
    const buf=enc.toUpperCase()==='B'?Buffer.from(txt,'base64')
      :Buffer.from(txt.replace(/_/g,' ').replace(/=([0-9A-F]{2})/gi,(_,h)=>String.fromCharCode(parseInt(h,16))),'latin1');
    return buf.toString(/utf-?8/i.test(cs)?'utf8':'latin1');
  });
}

function separer(brut){
  const i=brut.search(/\r?\n\r?\n/);
  const tete=i<0?brut:brut.slice(0,i),corps=i<0?'':brut.slice(i).replace(/^\r?\n\r?\n/,'');
  const entetes={};
  for(const ligne of tete.replace(/\r?\n[ \t]+/g,' ').split(/\r?\n/)){
    const j=ligne.indexOf(':');
    // Le premier exemplaire d'un en-tête gagne : c'est le plus haut, posé par le dernier serveur (le nôtre). Un
    // Authentication-Results que l'expéditeur aurait écrit lui-même se trouve plus bas et ne compte jamais.
    const k=j>0?ligne.slice(0,j).trim().toLowerCase():'';
    if(k&&!(k in entetes))entetes[k]=decoderMot(ligne.slice(j+1).trim());
  }
  return {entetes,corps};
}

function decoderCorps(corps,encodage){
  const e=(encodage||'').toLowerCase();
  if(e==='base64')return Buffer.from(corps.replace(/\s/g,''),'base64');
  if(e==='quoted-printable')return Buffer.from(corps.replace(/=\r?\n/g,'').replace(/=([0-9A-F]{2})/gi,(_,h)=>String.fromCharCode(parseInt(h,16))),'latin1');
  return Buffer.from(corps,'utf8');
}

function parties(brut,out){
  const {entetes,corps}=separer(brut);
  const type=entetes['content-type']||'text/plain';
  const frontiere=/boundary="?([^";]+)"?/i.exec(type)?.[1];
  if(/^multipart\//i.test(type)&&frontiere){
    for(const p of corps.split('--'+frontiere).slice(1)){
      if(p.startsWith('--'))break;
      parties(p.replace(/^\r?\n/,''),out);
    }
    return;
  }
  // Mail transféré « en pièce jointe » : on garde le mail d'origine entier, à déballer.
  if(/^message\/rfc822/i.test(type)){out.joints.push(decoderCorps(corps,entetes['content-transfer-encoding']).toString('utf8'));return;}
  const nom=/(?:file)?name="?([^";]+)"?/i.exec((entetes['content-disposition']||'')+';'+type)?.[1];
  const octets=decoderCorps(corps,entetes['content-transfer-encoding']);
  const charset=/charset="?([^";]+)"?/i.exec(type)?.[1]||'utf-8';
  if(/^text\//i.test(type)){
    let texte=octets.toString(/utf-?8/i.test(charset)?'utf8':'latin1');
    if(/html/i.test(type)){
      // Liens : l'adresse réelle ET le texte affiché, pour repérer les liens trompeurs.
      for(const [,href,interieur] of texte.matchAll(/<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi))
        out.liens.push({href:href.replace(/&amp;/g,'&').trim(),texte:interieur.replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim()});
      texte=texte.replace(/<br\s*\/?>/gi,'\n').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&');
    }else if(/xml/i.test(type))texte=texte.replace(/<[^>]+>/g,' ');
    else for(const [u] of texte.matchAll(/https?:\/\/[^\s<>"')]+/g))out.liens.push({href:u,texte:u});
    (nom?out.pieces:out.textes).push(nom?{nom,texte}:texte);
  }else if(nom){
    // Facture électronique en XML (UBL, CII) jointe telle quelle : l'IBAN y est un champ structuré.
    const xml=/xml/i.test(type)||/\.xml$/i.test(nom);
    out.pieces.push({nom,type,octets,...(/pdf/i.test(type)||/\.pdf$/i.test(nom)?{texte:textePdf(octets)}:xml?{texte:octets.toString('utf8').replace(/<[^>]+>/g,' ')}:{})});
  }
}

export const adresse=s=>(/<([^>]+)>/.exec(s||'')?.[1]||s||'').trim().toLowerCase();
export const domaine=s=>adresse(s).split('@')[1]||'';

export function lireEml(brut){
  const {entetes}=separer(brut);
  const out={textes:[],pieces:[],liens:[],joints:[]};
  parties(brut,out);
  return {
    de:adresse(entetes.from),nomDe:(entetes.from||'').replace(/<[^>]+>/,'').replace(/"/g,'').trim(),
    repondreA:entetes['reply-to']?adresse(entetes['reply-to']):null,
    objet:entetes.subject||'',date:entetes.date?new Date(entetes.date):null,
    texte:out.textes.join('\n'),pieces:out.pieces,liens:out.liens,joints:out.joints,entetes,
  };
}
