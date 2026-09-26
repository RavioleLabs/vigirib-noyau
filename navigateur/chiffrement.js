// Chiffrement dans le navigateur des identifiants de connexion (WebCrypto, RSA-OAEP SHA-256).
// Seule la clé privée de Vigirib, conservée hors du site, peut les lire. Rien ne part en clair.
export const LIMITE=446; // octets au plus pour une clé RSA de 4096 bits avec OAEP SHA-256

const b64=octets=>{let s='';for(const o of octets)s+=String.fromCharCode(o);return btoa(s);};

export async function chiffrer(donnees,clePublicPem){
  const der=Uint8Array.from(atob(clePublicPem.replace(/-----[^-]+-----|\s/g,'')),c=>c.charCodeAt(0));
  const cle=await crypto.subtle.importKey('spki',der,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
  const clair=new TextEncoder().encode(JSON.stringify(donnees));
  if(clair.length>LIMITE)throw Error('Les informations sont trop longues pour être chiffrées.');
  return b64(new Uint8Array(await crypto.subtle.encrypt({name:'RSA-OAEP'},cle,clair)));
}

export const DEBUT='-----DEBUT CONNEXION VIGIRIB-----',FIN='-----FIN CONNEXION VIGIRIB-----';
export const bloc=chiffre=>`${DEBUT}\n${chiffre.replace(/.{1,64}/g,'$&\n')}${FIN}`;

// Chiffrement hybride pour les listes (import des IBAN de référence) : clé AES-256-GCM aléatoire, données compressées
// puis chiffrées, clé AES chiffrée par RSA-OAEP. Format : [2 octets longueur clé][clé chiffrée][IV 12 octets][données].
export const DEBUT_LISTE='-----DEBUT LISTE VIGIRIB-----',FIN_LISTE='-----FIN LISTE VIGIRIB-----';
export async function chiffrerListe(donnees,clePublicPem){
  const der=Uint8Array.from(atob(clePublicPem.replace(/-----[^-]+-----|\s/g,'')),c=>c.charCodeAt(0));
  const rsa=await crypto.subtle.importKey('spki',der,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
  const aes=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
  const brut=new Uint8Array(await crypto.subtle.exportKey('raw',aes));
  const cleChiffree=new Uint8Array(await crypto.subtle.encrypt({name:'RSA-OAEP'},rsa,brut));
  const flux=new Blob([new TextEncoder().encode(JSON.stringify(donnees))]).stream().pipeThrough(new CompressionStream('deflate-raw'));
  const compresse=new Uint8Array(await new Response(flux).arrayBuffer());
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const chiffre=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},aes,compresse));
  const tout=new Uint8Array(2+cleChiffree.length+12+chiffre.length);
  tout[0]=cleChiffree.length>>8;tout[1]=cleChiffree.length&255;tout.set(cleChiffree,2);tout.set(iv,2+cleChiffree.length);tout.set(chiffre,14+cleChiffree.length);
  return `${DEBUT_LISTE}\n${b64(tout).replace(/.{1,64}/g,'$&\n')}${FIN_LISTE}`;
}
