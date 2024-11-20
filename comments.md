setup_2.py:

Not sure I would have put a class in the setup script. You use the methods as if they were static anyways (the NetworkHandler instance is never reused, instead you instantiate the thing each time you need a method, might as well just have a flat hierarchy).
line 10: You import * from this module later so why do you define an alias here? I would prefer calling the methods from an alias to importing *, always good to know where things came from when you are debugging.
line 16: please don't import *, import the methods that you need explicitly.

why the name setup_2? Is there a setup.py somewhere that I didn't see? :)

Good job logging! good to see what's going on.



config.py:

INTERNET_IFACE
Can you add a small description on how people are supposed to find these things? (e.g., ip addr show for unix systems...)

AP_IFACE
Document that people need an antenna (add to README)


Add rust compiler to the README


Getting the following error when installing requirements.txt
ERROR: Failed building wheel for signal_protocol
Failed to build signal_protocol
ERROR: ERROR: Failed to build installable wheels for some pyproject.toml based projects (signal_protocol)


=> Need to add the requirement for building wheels to the README which needs to happen before installing requirements.

-> need docker, how to install? I used snap and the next commands did not succeed.

not sure if sudo is really needed but it wouldn't run without it for me
```
sudo docker pull quay.io/pypa/manylinux2014_x86_64

sudo docker run --rm -v `pwd`:/io quay.io/pypa/manylinux2014_x86_64 /io/build-wheels.sh
```
Second command doesn't work with the following error:
"
/usr/local/bin/manylinux-entrypoint: line 13: /io/build-wheels.sh: No such file or directory
"
we are not sure why, would be good to include more detailed instructions.


```
pip install -U -r requirements.txt
```

fetching things for signal_protocol doesn't work. What wasn't installed yet was `build-essential`, which needs to be installed before trying to get the requirements.

But it still doesn't work. Error:

```
 Running `/tmp/pip-install-lob8wo0y/signal-protocol_c7d1b98ed7f24614b4bfae75774ed970/target/release/build/libsignal-protocol-14f4d9774c809039/build-script-build`
      error: failed to run custom build command for `libsignal-protocol v0.1.0 (https://github.com/signalapp/libsignal?tag=v0.59.0#826ee07b)`


...

note: This error originates from a subprocess, and is likely not a problem with pip.
  ERROR: Failed building wheel for signal_protocol
Failed to build signal_protocol
ERROR: ERROR: Failed to build installable wheels for some pyproject.toml based projects (signal_protocol)

```


db:
#33: No need to reference 'previous implementations' here I don't think it adds useful information to anyone external.

- Conversation:
Could we get rid of the 'initiated by victim' boolean by defining an ordering depending on the fields?
For example: 
aci1 -> aci_initiator
...
aci2 -> aci_respondent


src:
utils.py:
- remove make_kyber_record according to Aditz :)

.gitignore:
probably a good idea to add config.py and let people know how they should name it. For now 
this approach is fine though I do think we should probably migrate to a yaml setup. Then the 
config file could be in a subfolder. I did the same thing for feature-patch maybe this code could be reused.