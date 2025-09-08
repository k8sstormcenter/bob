#!/bin/bash
for file in all-bobs/*_bob.yaml; do
    kubectl apply -f $file;
done
