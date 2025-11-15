package backdoordetected;

import com.javadeobfuscator.deobfuscator.Deobfuscator;
import com.javadeobfuscator.deobfuscator.config.Configuration;
import com.javadeobfuscator.deobfuscator.config.TransformerConfig;
import com.javadeobfuscator.deobfuscator.transformers.general.peephole.PeepholeOptimizer;
import com.javadeobfuscator.deobfuscator.transformers.zelix.FlowObfuscationTransformer;
import com.javadeobfuscator.deobfuscator.transformers.general.removers.IllegalSignatureRemover;
import com.javadeobfuscator.deobfuscator.transformers.allatori.StringEncryptionTransformer;

import java.io.File;
import java.nio.file.Path;
import java.util.logging.Logger;
import java.util.Collections;
import java.util.ArrayList;
import com.javadeobfuscator.deobfuscator.executor.exceptions.ExecutionException;
import java.util.List;

public class DeobfuscationPipeline {

    private static final Logger logger = StandaloneLogger.getLogger();

    public Path deobfuscate(Path obfuscatedJar) {
        logger.info("[Deobfuscation] Starting deobfuscation for: " + obfuscatedJar.getFileName());

        try {
            File input = obfuscatedJar.toFile();
            File output = new File(obfuscatedJar.getParent().toFile(),
                    obfuscatedJar.getFileName().toString().replace(".jar", "-deobf.jar"));

            Configuration config = new Configuration();
            config.setInput(input);
            config.setOutput(output);

            List<File> classpathFiles = new ArrayList<>();
            classpathFiles.add(input);

            File javaHomeDir = new File(System.getProperty("java.home"));
            File libDir = new File(javaHomeDir, "lib");
            if (libDir.isDirectory()) {
                File[] jars = libDir.listFiles((dir, name) -> name.endsWith(".jar"));
                if (jars != null) {
                    Collections.addAll(classpathFiles, jars);
                }
            }
            File jmodsDir = new File(javaHomeDir, "jmods");
            if (jmodsDir.isDirectory()) {
                File[] jmods = jmodsDir.listFiles((dir, name) -> name.endsWith(".jmod"));
                if (jmods != null) {
                    Collections.addAll(classpathFiles, jmods);
                }
            }

            config.setPath(classpathFiles);

            config.setTransformers(new ArrayList<>());

            config.getTransformers().add(new TransformerConfig(StringEncryptionTransformer.class));
            config.getTransformers().add(new TransformerConfig(
                com.javadeobfuscator.deobfuscator.transformers.stringer.StringEncryptionTransformer.class
            ));
            config.getTransformers().add(new TransformerConfig(
                com.javadeobfuscator.deobfuscator.transformers.dasho.StringEncryptionTransformer.class
            ));

            config.getTransformers().add(new TransformerConfig(IllegalSignatureRemover.class));
            config.getTransformers().add(new TransformerConfig(PeepholeOptimizer.class));
            config.getTransformers().add(new TransformerConfig(FlowObfuscationTransformer.class));

            Deobfuscator deobfuscator = new Deobfuscator(config);
            try {
                deobfuscator.start();
            } catch (com.javadeobfuscator.deobfuscator.exceptions.NoClassInPathException e) {
                logger.warning("[Deobfuscation] Missing runtime class (ignored): " + e.getMessage());
            }
            logger.info("[Deobfuscation] Deobfuscation finished: " + output.getName());
            return output.toPath();
        } catch (Throwable e) {
            File output = new File(obfuscatedJar.getParent().toFile(),
                    obfuscatedJar.getFileName().toString().replace(".jar", "-deobf.jar"));

            if (output.exists() && output.length() > 0) {
                logger.warning("[Deobfuscation] Partial deobfuscation may have completed despite errors.");
                logger.warning("    Error: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                return output.toPath();
            }

            logger.warning("[Deobfuscation] Failed and no output file was created. Falling back to original JAR.");
            logger.fine("    Detailed error: " + e.getMessage());
            return obfuscatedJar;
        }
    }
}
