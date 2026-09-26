# Vigirib, le noyau public

[Vigirib](https://vigirib.com) alerte les entreprises quand l’IBAN d’un fournisseur change dans leurs mails, même quand le mail vient de la vraie adresse du fournisseur, piratée.

Ce dépôt publie **le code de Vigirib qui touche à vos données**, pour que chacun puisse vérifier nos promesses plutôt que nous croire sur parole.

| Promesse | Où la vérifier |
| --- | --- |
| La boîte d’un client est lue en lecture seule : envoyer, supprimer ou déplacer un mail est refusé par le code | `lib/imap.mjs` (liste blanche de commandes) |
| Chaque mail transféré est supprimé de notre boîte juste après l’analyse | `lib/reception.mjs` |
| Aucun IBAN n’est stocké en clair : empreinte HMAC-SHA256 avec une clé propre à chaque entreprise | `lib/registre.mjs`, `lib/empreinte.mjs` |
| Les codes d’accès et les IBAN de référence sont chiffrés dans le navigateur | `navigateur/chiffrement.js`, `outils/dechiffrer.mjs`, `outils/importer-ibans.mjs` |
| Une alerte ne contient jamais d’IBAN complet | `lib/alerte.mjs`, `lib/alerte-mail.mjs` |
| Un tiers ne peut pas déclencher d’alerte chez un client ni recevoir de réponse sans authentification | `lib/reception.mjs` |

Chaque promesse a son test : `test/promesses.test.mjs`.

## Ce qui n’est pas publié

Les règles de détection (comment Vigirib repère un faux RIB, un domaine imité ou un hameçonnage). Les publier aiderait les fraudeurs à les contourner. Elles reçoivent un mail et rendent un verdict ; tout ce qui entoure ce verdict (lecture, stockage, suppression, alerte) est ici.

## Lancer les tests

Aucune dépendance : Node.js 22 ou plus.

```
npm test
```

## Signaler une faille

Écrivez à contact@vigirib.com. Voir aussi https://vigirib.com/.well-known/security.txt.

## Licence

[EUPL-1.2](LICENSE), la licence libre de la Commission européenne.
