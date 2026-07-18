@echo off
nrfjprog -f nrf52 --snr 683609980 --program "%~dp0%~nx1" --sectorerase --verify --reset
