using CodeCake.Abstractions;
using System.Collections.Generic;
using static CodeCake.Build;

namespace CodeCake
{

    public partial class YarnSolution : ICIPublishWorkflow
    {
        private ArtifactType _artifactType;

        public ArtifactType ArtifactType
        {
            get
            {
                if( _artifactType == null ) _artifactType = new YarnArtifactType( _globalInfo, this );
                return _artifactType;
            }
        }

        public void Pack() => RunPack();
    }


    public partial class Build
    {
        /// <summary>
        /// Supports NPM packages.
        /// </summary>
        public class YarnArtifactType : ArtifactType
        {
            public YarnArtifactType( StandardGlobalInfo globalInfo, YarnSolution solution )
                : base( globalInfo, "NPM" )
            {
                Solution = solution;
            }

            public YarnSolution Solution { get; }

            protected override IEnumerable<ILocalArtifact> GetLocalArtifacts() => Solution.AllPublishedProjects;


            protected override IEnumerable<ArtifactFeed> GetRemoteFeeds()
            {if( GlobalInfo.BuildInfo.Version.PackageQuality <= CSemVer.PackageQuality.Stable ) yield return new AzureYarnFeed( this, "Signature-OpenSource", "NetCore3", "Feeds" );
if( GlobalInfo.BuildInfo.Version.PackageQuality >= CSemVer.PackageQuality.ReleaseCandidate ) yield return new YarnRemoteFeed( this, "NPMJS_ORG_PUSH_PAT", "https://registry.npmjs.org/", false );
}

            protected override IEnumerable<ArtifactFeed> GetLocalFeeds()
            {
                return new ArtifactFeed[] {
                    new YarnLocalFeed( this, GlobalInfo.LocalFeedPath )
                };
            }
        }
    }
}
