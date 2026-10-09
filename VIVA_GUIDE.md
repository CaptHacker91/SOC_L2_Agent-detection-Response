# Viva Guide

## Why normalize events?
Different sources expose different field names. The normalizer creates one stable contract for downstream detection and investigation.

## Why separate severity, risk and confidence?
Severity expresses triage priority, risk is a configured/derived score, and confidence expresses confidence in the observed detection signal. None is equivalent to proof of compromise.

## Why keep analyst confirmation separate?
A SOC platform assists an analyst; it should not silently turn a rule match into a confirmed incident.

## Why persist cases?
Investigation decisions, assignments and status should survive a page refresh or application restart in a prototype case-management workflow.

## Why show provenance?
It lets the analyst explain where a normalized field came from and makes the investigation traceable.

## Why is AI optional?
The core pipeline must remain useful when the AI provider is unavailable. AI is a bounded assistant, not the source of truth.
