import android.databinding.tool.ext.capitalizeUS
import java.security.MessageDigest
import org.apache.tools.ant.filters.ReplaceTokens
import org.apache.tools.ant.filters.FixCrLfFilter
import org.apache.commons.codec.binary.Hex
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import java.util.TreeSet
import java.nio.file.Paths

plugins {
    alias(libs.plugins.agp.lib)
}

val moduleId: String by rootProject.extra
val moduleName: String by rootProject.extra
val verCode: Int by rootProject.extra
val verName: String by rootProject.extra
val minAPatchVersion: Int by rootProject.extra
val minKsuVersion: Int by rootProject.extra
val minKsudVersion: Int by rootProject.extra
val maxKsuVersion: Int by rootProject.extra
val minMagiskVersion: Int by rootProject.extra
val commitHash: String by rootProject.extra

android.buildFeatures {
    androidResources = false
    buildConfig = false
}

androidComponents.onVariants { variant ->
    val variantLowered = variant.name.lowercase()
    val variantCapped = variant.name.capitalizeUS()
    val buildTypeLowered = variant.buildType?.lowercase()

    val moduleDir = layout.buildDirectory.dir("outputs/module/$variantLowered")
    val zipFileName = "$moduleName-$verName-$verCode-$commitHash-$buildTypeLowered.zip".replace(' ', '-')

    val prepareModuleFilesTask = task<Sync>("prepareModuleFiles$variantCapped") {
        group = "module"
        dependsOn(":loader:assemble$variantCapped", ":zygiskd:buildAndStrip")

        into(moduleDir) {
            from("${rootProject.projectDir}/README.md")
            from("$projectDir/src") {
                exclude("module.prop", "customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh")
                filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
            }
            from("$projectDir/src") {
                include("module.prop")
                expand(
                    "moduleId" to moduleId,
                    "moduleName" to moduleName,
                    "versionName" to "$verName ($verCode-$commitHash-$variantLowered)",
                    "versionCode" to verCode
                )
            }
            from("$projectDir/src") {
                include("customize.sh", "post-fs-data.sh", "service.sh", "uninstall.sh")
                val tokens = mapOf(
                    "DEBUG" to if (buildTypeLowered == "debug") "true" else "false",
                    "MIN_APATCH_VERSION" to minAPatchVersion.toString(),
                    "MIN_KSU_VERSION" to minKsuVersion.toString(),
                    "MIN_KSUD_VERSION" to minKsudVersion.toString(),
                    "MAX_KSU_VERSION" to maxKsuVersion.toString(),
                    "MIN_MAGISK_VERSION" to minMagiskVersion.toString(),
                )
                filter<ReplaceTokens>("tokens" to tokens)
                filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
            }
            into("bin") {
                from(project(":zygiskd").layout.buildDirectory.getAsFile().get())
                include("**/zygiskd")
            }
            into("lib") {
                from(project(":loader").layout.buildDirectory.file("intermediates/stripped_native_libs/$variantLowered/out/lib"))
            }
            into("webroot") {
                from("${rootProject.projectDir}/webroot")
            }
        }
    }

    val signModuleTask = task("signModule$variantCapped") {
        group = "module"
        dependsOn(prepareModuleFilesTask)

        doLast {
            val root = moduleDir.get().asFile
            val privateKeyFile = file("private_key")
            
            if (privateKeyFile.exists()) {
                logger.lifecycle("=== Starting module signing ===")

                val privateKey = privateKeyFile.readBytes()
                val publicKey = file("public_key").readBytes()
                val namedSpec = NamedParameterSpec("ed25519")
                val privKeySpec = EdECPrivateKeySpec(namedSpec, privateKey)
                val kf = KeyFactory.getInstance("ed25519")
                val privKey = kf.generatePrivate(privKeySpec)
                val sig = Signature.getInstance("ed25519")

                fun File.sha(realFile: File? = null) {
                    sig.update(this.name.toByteArray())
                    sig.update(0) // null-terminated string
                    val real = realFile ?: this
                    val buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(real.length()).array()
                    sig.update(buffer)
                    real.forEachBlock { bytes, size ->
                        sig.update(bytes, 0, size)
                    }
                }

                // Helper function to generate architecture signature
                fun generateArchSignature(name: String, abi: String, is64Bit: Boolean) {
                    val set = TreeSet<Pair<File, File?>> { o1, o2 ->
                        o1.first.path.replace("\\", "/")
                            .compareTo(o2.first.path.replace("\\", "/"))
                    }

                    val archSuffix = if (is64Bit) "64" else "32"
                    val pathSuffix = if (is64Bit) "lib64" else "lib"

                    set.add(Pair(root.resolve("module.prop"), null))
                    set.add(Pair(root.resolve("sepolicy.rule"), null))
                    set.add(Pair(root.resolve("post-fs-data.sh"), null))
                    set.add(Pair(root.resolve("service.sh"), null))
                    set.add(Pair(root.resolve("$pathSuffix/libzygisk.so"), root.resolve("lib/$abi/libzygisk.so")))
                    set.add(Pair(root.resolve("bin/zygisk-ptrace$archSuffix"), root.resolve("lib/$abi/libzygisk_ptrace.so")))
                    set.add(Pair(root.resolve("bin/zygiskd$archSuffix"), root.resolve("bin/$abi/zygiskd")))

                    sig.initSign(privKey)
                    set.forEach { it.first.sha(it.second) }
                    val signFile = root.resolve(name)
                    signFile.writeBytes(sig.sign())
                    signFile.appendBytes(publicKey)
                    logger.lifecycle("Generated signature file: $name")
                }

                // Generate SHA256 hashes for all files
                fun generateSha256Hashes() {
                    root.walkTopDown().forEach { file ->
                        if (!file.isFile || file.isHidden) return@forEach
                        val md = MessageDigest.getInstance("SHA-256")
                        file.forEachBlock(4096) { bytes, size ->
                            md.update(bytes, 0, size)
                        }
                        file.resolveSibling("${file.name}.sha256").writeText(Hex.encodeHexString(md.digest()))
                    }
                    logger.lifecycle("Generated SHA256 hashes for all files")
                }

                // Generate all necessary signatures
                generateArchSignature("machikado.arm64", "arm64-v8a", true)
                generateArchSignature("machikado.arm", "armeabi-v7a", false)
                generateArchSignature("machikado.x86_64", "x86_64", true)
                generateArchSignature("machikado.x86", "x86", false)

                generateSha256Hashes()

                // Master signature
                sig.initSign(privKey)
                root.walkTopDown().forEach { file ->
                    if (!file.isFile || file.isHidden) return@forEach
                    file.sha(file)
                }

                val misakiSignatureFile = root.resolve("misaki.sig")
                misakiSignatureFile.writeBytes(sig.sign())
                misakiSignatureFile.appendBytes(publicKey)
                logger.lifecycle("Generated master signature file: misaki.sig")
                
            } else {
                logger.warn("No private_key found, this build will not be signed")
                
                // Create empty signature files
                listOf("machikado.arm64", "machikado.arm", "machikado.x86_64", "machikado.x86", "misaki.sig")
                    .map { root.resolve(it) }
                    .forEach { it.createNewFile() }
                
                // Generate SHA256 hashes for all files
                root.walkTopDown().forEach { file ->
                    if (!file.isFile || file.isHidden) return@forEach
                    val md = MessageDigest.getInstance("SHA-256")
                    file.forEachBlock(4096) { bytes, size ->
                        md.update(bytes, 0, size)
                    }
                    file.resolveSibling("${file.name}.sha256").writeText(Hex.encodeHexString(md.digest()))
                }
                logger.lifecycle("Generated SHA256 hashes for all files (no signatures)")
            }
        }
    }

    val zipTask = task<Zip>("zip$variantCapped") {
        group = "module"
        dependsOn(signModuleTask)
        archiveFileName.set(zipFileName)
        destinationDirectory.set(layout.buildDirectory.dir("outputs/release").get().asFile)
        from(moduleDir)
    }

    // Create push and install tasks
    fun createInstallTask(name: String, variant: String, command: String): TaskProvider<Task> {
        return tasks.register("${name}$variant") {
            group = "module"
            dependsOn(zipTask)
            doLast {
                val zipFile = zipTask.outputs.files.singleFile
                exec {
                    commandLine("adb", "push", zipFile.path, "/data/local/tmp")
                }
