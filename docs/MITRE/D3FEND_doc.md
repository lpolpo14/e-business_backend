# MITRE D3FEND Documentation of Use

Sadly, there is no official documentation for the d3fend.json file. Here are some important observations:

- Similarly to ATT&CK, there are tactics and there defensive techniques.
- All the important objects we want to download are located inside the @graph key.
- d3f:d3fend-id key matches the actual ID on the d3fend site.
- Every tactic is of d3f:DefensiveTactic Type as shown in the following example:

```json
      "@id": "d3f:Evict",
      "@type": [
        "owl:Class",
        "owl:NamedIndividual",
        "d3f:DefensiveTactic"
      ],
```

- Every Category of a specific tactic has this inside:

```json
"rdfs:subClassOf": [
        {
          "@id": "d3f:DefensiveTechnique"
        },
        {
          "@id": "_:Nf293a6b8083d4dfca6efbe702698dee3"
        }
      ]
```

This is how we retrieve them. Also, to retrieve their full name we use rdfs:label (ex "rdfs:label": "Network Mapping",...)

- What about a specific technique though? rdfs:subClassOf contains as the first element the id of the d3f superclass. The issue is that that holds true for other cases as well..
- The most important observation is the fact that each object that is of interest to us starts with D3-... as seen here:

```json
"d3f:d3fend-id": "D3-OE"
```

This gives us an easy way to query for these objects. This creates a bit of an issue though with the possible subclasses. Nevertheless, one can start creating a prototype parser.

Our first prototype successfully finds all the correct Tactics (7 Tactics), but returns one extra technique (249 instead of 248)... What may be the cause?
The cause is that there are indeed 249 tactics. Our prototype is excellent. Where is that one technique on the main site then? Bizarre.
