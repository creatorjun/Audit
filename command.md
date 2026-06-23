```
git clone https://github.com/creatorjun/Audit.git
cd Audit
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
make install DESTDIR=../dist
cd ..
tar -czf audit-daemon-1.0.0-ol8.tar.gz -C dist .
```

```
cd /root && tar -xzf audit-daemon-1.0.0-ol8.tar.gz -C / && systemctl daemon-reload && systemctl enable --now audit-daemon
systemctl status audit-daemon
journalctl -u audit-daemon -f
```