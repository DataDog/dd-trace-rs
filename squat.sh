successfully_pushed=()
while read name; do
    sed -i '' "s#name = \".*\"#name = \"$name\"#" ./placeholder/Cargo.toml
    cargo publish -p $name --allow-dirty
    res=$?
    if [ $res -eq 0 ] ; then
        successfully_pushed+=($name)
    else
        break
    fi
    cargo owner --add github:Datadog:libdatadog-owners $name
done < to_squat 

echo $successfully_pushed

echo "Successfully pushed:"
for name in "${successfully_pushed[@]}"; do
    echo "\t" $name
done

for name in "${successfully_pushed[@]}"; do
    echo $name >> pushed
    sed -i '' "/$name/d" to_squat
done
